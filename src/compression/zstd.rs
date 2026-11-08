//! Zstandard compression of async streams (br-asupersync-t1fblr.31).
//!
//! [`ZstdEncoder`] wraps an [`AsyncWrite`] and compresses everything written
//! through it. [`ZstdDecoder`] wraps an [`AsyncRead`] and decompresses what
//! it reads. Each poll performs a bounded number of codec and stream calls.
//! Neither adapter does I/O other than on the stream it wraps, spawns tasks,
//! or needs a `Cx`.
//!
//! # Wire format
//!
//! The encoder writes standard RFC 8878 frames. It cuts its input into
//! independent frames of at most `frame_size` bytes (1 MiB by default). Each
//! frame declares its content size and, by default, an XXH64 checksum, so
//! any Zstandard decoder (`zstd -d`, libzstd) reads the result. The decoder
//! reads any frame without a dictionary, including concatenated and
//! skippable frames.
//!
//! # Limits
//!
//! A [`ZstdDecoder`] always takes explicit [`DecodeLimits`]. They bound its
//! total output and each frame's window, so a small hostile input cannot
//! make it allocate or produce more than the caller allows.
//!
//! # Errors
//!
//! A stream that ends inside a frame, or contains no frame at all, fails
//! with [`io::ErrorKind::UnexpectedEof`]. Any other decoding failure,
//! including an exceeded limit, fails with [`io::ErrorKind::InvalidData`].
//! The [`DecodeError`] is the error's source. The first codec error is final.
//! Source I/O errors are returned unchanged. If the source permits a retry,
//! the decoder retains any compressed bytes reported alongside that error.
//!
//! # Cancel safety
//!
//! All codec state lives in the adapter. A dropped read or write future
//! therefore loses nothing, as long as the adapter is kept:
//! - `poll_write` takes input only when it returns `Ok(n)`. The encoder owns
//!   those bytes until they reach the wrapped writer.
//! - `poll_flush` and `poll_shutdown` can be retried after `Pending`.
//! - `poll_read` keeps whatever compressed input it consumed. A read that
//!   returns no bytes has delivered none.
//!
//! Dropping a [`ZstdEncoder`] discards its buffered input and does not end
//! the stream. Call `shutdown` first: it compresses the last frame and shuts
//! the wrapped writer down.
//!
//! Decoded bytes are provisional until their frame's checksum is verified.
//! After an error, treat everything read from that stream as untrusted.
//!
//! # Work per poll
//!
//! The encoder makes at most 32 codec or wrapped-writer calls per poll. The
//! allowance is shared by staging writes, encoding, flushing and shutdown;
//! an always-ready writer cannot keep a single poll draining indefinitely.
//! On exhaustion the encoder wakes itself before yielding. A codec call
//! can still compress a whole frame, so this bounds the number of operations,
//! not wall-clock time. Smaller frames reduce the maximum compression work
//! in one call, at some cost in ratio.
//! The decoder performs at most 32 codec steps per poll, each processing at
//! most one bounded block, and then wakes itself before yielding. Empty and
//! skippable frames therefore cannot keep a single read poll running forever.
//!
//! # Example
//!
//! ```
//! use asupersync::compression::zstd::{DecodeLimits, ZstdDecoder, ZstdEncoder};
//! use asupersync::io::{AsyncReadExt, AsyncWriteExt, duplex};
//! use asupersync::runtime::RuntimeBuilder;
//!
//! let runtime = RuntimeBuilder::current_thread().build().unwrap();
//! runtime.block_on(async {
//!     let (wire_in, wire_out) = duplex(64 * 1024);
//!     let mut encoder = ZstdEncoder::new(wire_in);
//!     encoder.write_all(b"hello, hello, hello").await.unwrap();
//!     encoder.shutdown().await.unwrap();
//!
//!     let mut decoder = ZstdDecoder::new(wire_out, DecodeLimits::new(1 << 20));
//!     let mut text = Vec::new();
//!     decoder.read_to_end(&mut text).await.unwrap();
//!     assert_eq!(text, b"hello, hello, hello");
//! });
//! ```

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use asupersync_zstd::{StreamDecoder, StreamEncodeError, StreamEncoder, StreamStatus};

use crate::io::{AsyncRead, AsyncWrite, ReadBuf};

pub use asupersync_zstd::{DecodeError, DecodeLimits, EncodeParams, Level};

/// The frame size [`ZstdEncoder::new`] uses: 1 MiB.
pub const DEFAULT_FRAME_SIZE: usize = StreamEncoder::DEFAULT_FRAME_SIZE;

/// The largest frame size [`ZstdEncoder::with_params`] accepts: 8 MiB, the
/// default window limit of [`DecodeLimits`].
pub const MAX_FRAME_SIZE: usize = StreamEncoder::MAX_FRAME_SIZE;

/// Bytes each adapter stages between the codec and the wrapped stream.
const STAGING: usize = 32 * 1024;
const POLL_STEPS: usize = 32;

fn encode_error(error: StreamEncodeError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error)
}

fn decode_error(error: DecodeError) -> io::Error {
    let kind = if error == DecodeError::Truncated {
        io::ErrorKind::UnexpectedEof
    } else {
        io::ErrorKind::InvalidData
    };
    io::Error::new(kind, error)
}

/// Compresses everything written to it into Zstandard frames, which it writes
/// to the wrapped [`AsyncWrite`]. See the [module documentation](crate::compression::zstd).
pub struct ZstdEncoder<W> {
    inner: W,
    encoder: StreamEncoder,
    /// Compressed bytes not yet accepted by `inner`: `staged[written..filled]`.
    staged: Box<[u8]>,
    written: usize,
    filled: usize,
    /// `shutdown` started: input is refused and the last frame is draining.
    finishing: bool,
    /// The encoder produced its last byte (it may still be staged).
    finished: bool,
}

impl<W> ZstdEncoder<W> {
    /// Compresses into `inner` with [`Level::Fast`], content checksums and
    /// frames of [`DEFAULT_FRAME_SIZE`] bytes.
    #[must_use]
    pub fn new(inner: W) -> Self {
        let encoder = StreamEncoder::new(EncodeParams::new(Level::Fast), DEFAULT_FRAME_SIZE)
            .expect("the default frame size is in range");
        Self::with_encoder(inner, encoder)
    }

    /// Compresses into `inner` with `params`, cutting the input into frames of
    /// at most `frame_size` bytes.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidInput`] when `frame_size` is zero or larger
    /// than [`MAX_FRAME_SIZE`].
    pub fn with_params(inner: W, params: EncodeParams, frame_size: usize) -> io::Result<Self> {
        let encoder = StreamEncoder::new(params, frame_size).map_err(encode_error)?;
        Ok(Self::with_encoder(inner, encoder))
    }

    fn with_encoder(inner: W, encoder: StreamEncoder) -> Self {
        Self {
            inner,
            encoder,
            staged: vec![0; STAGING].into_boxed_slice(),
            written: 0,
            filled: 0,
            finishing: false,
            finished: false,
        }
    }

    /// The wrapped writer.
    #[must_use]
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// The wrapped writer. Writing to it directly corrupts the stream.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Returns the wrapped writer. Input not yet compressed, and compressed
    /// bytes not yet written, are lost: call `shutdown` first.
    #[must_use]
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: AsyncWrite + Unpin> ZstdEncoder<W> {
    /// Writes the staged compressed bytes to `inner`.
    fn poll_drain(&mut self, cx: &mut Context<'_>, remaining: &mut usize) -> Poll<io::Result<()>> {
        while self.written < self.filled {
            ready!(Self::poll_step(cx, remaining));
            let pending = self.filled - self.written;
            match Pin::new(&mut self.inner).poll_write(cx, &self.staged[self.written..self.filled])
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(n)) if n > pending => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("writer reported {n} bytes written for {pending}"),
                    )));
                }
                Poll::Ready(Ok(n)) => self.written += n,
            }
        }
        self.written = 0;
        self.filled = 0;
        Poll::Ready(Ok(()))
    }

    /// Charges one codec or wrapped-writer call to the enclosing public poll.
    fn poll_step(cx: &Context<'_>, remaining: &mut usize) -> Poll<()> {
        if *remaining == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        *remaining -= 1;
        Poll::Ready(())
    }

    /// Stages what one codec call produced.
    fn stage(&mut self, output_written: usize) {
        self.written = 0;
        self.filled = output_written;
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for ZstdEncoder<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // Refused from the first `poll_shutdown`, even while it is still
        // draining staged bytes and has not reached the encoder yet.
        if this.finishing {
            return Poll::Ready(Err(encode_error(StreamEncodeError::Finished)));
        }
        let mut remaining = POLL_STEPS;
        loop {
            match this.poll_drain(cx, &mut remaining) {
                Poll::Ready(Ok(())) => {}
                other => return other.map_ok(|()| 0),
            }
            ready!(Self::poll_step(cx, &mut remaining));
            let progress = this
                .encoder
                .encode(buf, &mut this.staged)
                .map_err(encode_error)?;
            this.stage(progress.output_written);
            if progress.input_read > 0 || buf.is_empty() {
                return Poll::Ready(Ok(progress.input_read));
            }
            if progress.output_written == 0 {
                return Poll::Ready(Err(io::Error::other(
                    "zstd encoder accepted no input into an empty staging buffer",
                )));
            }
            // The encoder emitted the rest of an earlier frame and took no
            // input: write that out, then offer the input again.
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut remaining = POLL_STEPS;
        loop {
            match this.poll_drain(cx, &mut remaining) {
                Poll::Ready(Ok(())) => {}
                other => return other,
            }
            if this.finishing {
                break;
            }
            ready!(Self::poll_step(cx, &mut remaining));
            let progress = this.encoder.flush(&mut this.staged).map_err(encode_error)?;
            this.stage(progress.output_written);
            if progress.output_written == 0 {
                break;
            }
        }
        ready!(Self::poll_step(cx, &mut remaining));
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.finishing = true;
        let mut remaining = POLL_STEPS;
        loop {
            match this.poll_drain(cx, &mut remaining) {
                Poll::Ready(Ok(())) => {}
                other => return other,
            }
            if this.finished {
                break;
            }
            ready!(Self::poll_step(cx, &mut remaining));
            let progress = this.encoder.finish(&mut this.staged);
            this.stage(progress.output_written);
            if progress.status == StreamStatus::Finished {
                this.finished = true;
            } else if progress.output_written == 0 {
                return Poll::Ready(Err(io::Error::other(
                    "zstd encoder made no progress finishing the stream",
                )));
            }
        }
        ready!(Self::poll_step(cx, &mut remaining));
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// Shows the wrapped writer and buffer sizes, never buffered data.
impl<W: fmt::Debug> fmt::Debug for ZstdEncoder<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZstdEncoder")
            .field("inner", &self.inner)
            .field("encoder", &self.encoder)
            .field("staged", &(self.filled - self.written))
            .field("finishing", &self.finishing)
            .field("finished", &self.finished)
            .finish()
    }
}

/// Decompresses the Zstandard frames it reads from the wrapped
/// [`AsyncRead`], within explicit [`DecodeLimits`]. See the
/// [module documentation](crate::compression::zstd).
pub struct ZstdDecoder<R> {
    inner: R,
    decoder: StreamDecoder,
    /// Compressed bytes read from `inner` and not yet given to the decoder:
    /// `input[consumed..filled]`.
    input: Box<[u8]>,
    consumed: usize,
    filled: usize,
    /// `inner` reached end of file.
    eof: bool,
    /// The stream ended cleanly; every later read returns end of file.
    done: bool,
    /// A substituted input buffer makes the source's progress unknowable.
    read_buffer_replaced: bool,
}

impl<R> ZstdDecoder<R> {
    /// Decompresses what `inner` yields, within `limits`.
    #[must_use]
    pub fn new(inner: R, limits: DecodeLimits) -> Self {
        Self {
            inner,
            decoder: StreamDecoder::new(limits),
            input: vec![0; STAGING].into_boxed_slice(),
            consumed: 0,
            filled: 0,
            eof: false,
            done: false,
            read_buffer_replaced: false,
        }
    }

    /// The wrapped reader.
    #[must_use]
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// The wrapped reader. Reading from it directly corrupts the stream.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Returns the wrapped reader. Compressed bytes already read from it, and
    /// decoded bytes not yet returned, are lost.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: AsyncRead + Unpin> ZstdDecoder<R> {
    fn check_read_buffer(&self) -> io::Result<()> {
        if self.read_buffer_replaced {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "zstd source replaced the read buffer it was given; endpoint effects are unknown",
            ))
        } else {
            Ok(())
        }
    }

    /// Preserve in-place input before interpreting the source's poll status.
    fn poll_refill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.consumed = 0;
        self.filled = 0;
        let start = self.input.as_ptr();
        let offered = self.input.len();
        let mut read = ReadBuf::new(&mut self.input);
        let result = Pin::new(&mut self.inner).poll_read(cx, &mut read);
        if !crate::io::transfer_session::filled_in_place(read.filled(), start, offered) {
            self.read_buffer_replaced = true;
            return Poll::Ready(self.check_read_buffer());
        }
        self.filled = read.filled().len();
        match result {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending if self.filled == 0 => Poll::Pending,
            Poll::Pending | Poll::Ready(Ok(())) => {
                // Only an empty successful read establishes EOF. A pending
                // read with bytes has already made progress we can decode.
                self.eof = self.filled == 0;
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for ZstdDecoder<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.done || buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        this.check_read_buffer()?;
        for _ in 0..POLL_STEPS {
            if this.eof {
                let progress = this.decoder.finish(buf.unfilled()).map_err(decode_error)?;
                buf.advance(progress.output_written);
                if progress.status == StreamStatus::Finished {
                    this.done = true;
                    return Poll::Ready(Ok(()));
                }
                if progress.output_written > 0 {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(io::Error::other(
                    "zstd decoder made no progress at end of stream",
                )));
            }
            let progress = this
                .decoder
                .decode(&this.input[this.consumed..this.filled], buf.unfilled())
                .map_err(decode_error)?;
            this.consumed += progress.input_read;
            buf.advance(progress.output_written);
            if progress.output_written > 0 {
                return Poll::Ready(Ok(()));
            }
            if progress.input_read > 0 || progress.status == StreamStatus::FrameFinished {
                continue;
            }
            if this.consumed < this.filled {
                return Poll::Ready(Err(io::Error::other(
                    "zstd decoder made no progress with input pending",
                )));
            }
            match this.poll_refill(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// Shows the wrapped reader and buffer sizes, never buffered data.
impl<R: fmt::Debug> fmt::Debug for ZstdDecoder<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZstdDecoder")
            .field("inner", &self.inner)
            .field("decoder", &self.decoder)
            .field("buffered", &(self.filled - self.consumed))
            .field("eof", &self.eof)
            .field("done", &self.done)
            .field("read_buffer_replaced", &self.read_buffer_replaced)
            .finish()
    }
}
