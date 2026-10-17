//! Zstandard compression of async streams (br-asupersync-t1fblr.31).
//!
//! [`ZstdEncoder`] wraps an [`AsyncWrite`] and compresses everything written
//! through it. [`ZstdDecoder`] wraps an [`AsyncRead`] and decompresses what
//! it reads. Each poll drives the codec one bounded step. Neither adapter
//! does I/O other than on the stream it wraps, spawns tasks, or needs a `Cx`.
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
//! The [`DecodeError`] is the error's source. The first error is final.
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
//! The encoder compresses a frame when it fills, and on flush and shutdown.
//! That work happens inside a single poll: about 10 ms for a 1 MiB frame at
//! 100 MB/s. A smaller frame shortens each poll, at some cost in ratio.
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
use std::task::{Context, Poll};

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
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.filled {
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
        loop {
            match this.poll_drain(cx) {
                Poll::Ready(Ok(())) => {}
                other => return other.map_ok(|()| 0),
            }
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
        loop {
            match this.poll_drain(cx) {
                Poll::Ready(Ok(())) => {}
                other => return other,
            }
            if this.finishing {
                break;
            }
            let progress = this.encoder.flush(&mut this.staged).map_err(encode_error)?;
            this.stage(progress.output_written);
            if progress.output_written == 0 {
                break;
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.finishing = true;
        loop {
            match this.poll_drain(cx) {
                Poll::Ready(Ok(())) => {}
                other => return other,
            }
            if this.finished {
                break;
            }
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
        loop {
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
            if progress.input_read > 0 {
                continue;
            }
            if this.consumed < this.filled {
                return Poll::Ready(Err(io::Error::other(
                    "zstd decoder made no progress with input pending",
                )));
            }
            let mut read = ReadBuf::new(&mut this.input);
            match Pin::new(&mut this.inner).poll_read(cx, &mut read) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
            this.consumed = 0;
            this.filled = read.filled().len();
            this.eof = this.filled == 0;
        }
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
            .finish()
    }
}
