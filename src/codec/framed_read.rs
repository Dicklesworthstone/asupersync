//! Async framed reader combining `AsyncRead` with a `Decoder`.

use crate::bytes::BytesMut;
use crate::codec::Decoder;
use crate::io::{AsyncRead, ReadBuf};
use crate::stream::Stream;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Default read buffer capacity.
const DEFAULT_CAPACITY: usize = 8192;

/// Stack buffer size for reads.
const READ_BUF_SIZE: usize = 8192;
/// Cooperative cap on repeated read/decode passes inside one `poll_next`.
///
/// Without this bound, an always-ready reader that never produces a full frame
/// can monopolize a single executor turn indefinitely.
const MAX_READ_PASSES_PER_POLL: usize = 32;

/// Whether the buffered bytes may produce a frame or the transport must change
/// before decoding can make progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReadState {
    /// Buffered input or decoder state may now produce a frame.
    NeedsDecode,
    /// The last decode needed more input and the transport must be polled.
    NeedsRead,
}

/// Default upper bound, in bytes, on the partial-frame buffer
/// retained across `poll_next` calls.
///
/// 8 MiB plus the default four-byte length prefix accommodates one
/// `LengthDelimitedCodec` frame at its default `max_frame_length`.
/// Without this bound, a slowloris-style attacker can
/// stream just under `max_frame_length` bytes per connection without
/// ever producing a complete frame; the buffer grows monotonically
/// per connection and, multiplied by concurrent connections, exhausts
/// server memory. The cooperative `MAX_READ_PASSES_PER_POLL` budget
/// only yields the executor — it does NOT free the buffer.
/// (br-asupersync-bj427s.)
pub const DEFAULT_MAX_BUFFER_LEN: usize = 8 * 1024 * 1024 + 4;

/// Async framed reader that applies a `Decoder` to an `AsyncRead` source.
///
/// Implements `Stream` where each item is a decoded frame. Data is read
/// from the inner reader into an internal buffer, then the decoder extracts
/// complete frames.
///
/// # Cancel Safety
///
/// `poll_next` is cancel-safe. Partial data remains in the internal buffer
/// across cancellations. No decoded frame is lost unless it was already yielded.
///
/// # Memory bound (security)
///
/// Each instance carries a partial-frame buffer cap. The automatic limit is
/// the larger of [`DEFAULT_MAX_BUFFER_LEN`] (an 8 MiB payload plus four-byte
/// length prefix) and the decoder's finite
/// [`Decoder::max_buffered_frame_len`] hint. Unknown or unbounded hints keep
/// the bounded default. When inbound bytes would push the buffer past
/// this cap, `poll_next` yields
/// `Err(InvalidData)` rather than appending — the caller MUST treat
/// the FramedRead as terminated. Without this bound, a peer that
/// streams bytes without ever closing a frame causes unbounded
/// per-connection memory growth (canonical slowloris-on-framing
/// attack — see asupersync-bj427s).
///
/// Configure an absolute override with [`Self::with_max_buffer_len`]; a value
/// of `0` disables enforcement (matches the no-cap convention used elsewhere
/// in this crate). [`Self::effective_max_buffer_len`] reports the current
/// limit, including decoder configuration changes.
pub struct FramedRead<R, D> {
    inner: R,
    decoder: D,
    buffer: BytesMut,
    eof: bool,
    read_state: ReadState,
    max_buffer_len: usize,
    max_buffer_len_explicit: bool,
    /// br-asupersync-3asq77: once the decoder (or the read path) has
    /// surfaced an `Err`, the stream is poisoned. Subsequent
    /// `poll_next` calls return `Poll::Ready(None)` rather than
    /// re-decoding the same bytes (which would yield the same error in
    /// an infinite loop, hanging any caller using `collect` /
    /// `for_each`). Decoder-level recovery — when the codec knows how
    /// to advance past an offending frame — belongs in the decoder
    /// (see `LengthDelimitedCodec::Skip` from br-asupersync-o7e5xu);
    /// `FramedRead` itself has no way to know framing semantics, so
    /// the only correct policy here is fail-closed.
    poisoned: bool,
}

impl<R, D> FramedRead<R, D> {
    /// Creates a new `FramedRead` with the default buffer capacity.
    #[inline]
    pub fn new(inner: R, decoder: D) -> Self {
        Self::with_capacity(inner, decoder, DEFAULT_CAPACITY)
    }

    /// Creates a new `FramedRead` with the specified buffer capacity.
    pub fn with_capacity(inner: R, decoder: D, capacity: usize) -> Self {
        Self {
            inner,
            decoder,
            buffer: BytesMut::with_capacity(capacity),
            eof: false,
            read_state: ReadState::NeedsRead,
            max_buffer_len: DEFAULT_MAX_BUFFER_LEN,
            max_buffer_len_explicit: false,
            poisoned: false,
        }
    }

    /// Set the maximum byte length of the partial-frame buffer. When
    /// inbound bytes would push the buffer past this cap, `poll_next`
    /// yields `Err(InvalidData)` rather than appending. A value of `0`
    /// disables enforcement entirely (matches the no-cap convention
    /// used elsewhere in this crate). This explicit limit overrides the
    /// decoder's hint. Without an override, the automatic limit is the larger
    /// of [`DEFAULT_MAX_BUFFER_LEN`] and a finite decoder hint.
    /// (br-asupersync-bj427s.)
    #[must_use]
    pub fn with_max_buffer_len(mut self, max: usize) -> Self {
        self.max_buffer_len = max;
        self.max_buffer_len_explicit = true;
        self
    }

    /// Returns the configured partial-frame buffer limit in bytes.
    ///
    /// With no explicit override this is [`DEFAULT_MAX_BUFFER_LEN`]; a finite
    /// decoder hint may raise the automatic limit. Use
    /// [`Self::effective_max_buffer_len`] to include the current decoder hint.
    /// An explicit `0` indicates no cap.
    #[inline]
    #[must_use]
    pub fn max_buffer_len(&self) -> usize {
        self.max_buffer_len
    }

    /// Returns the read-buffer limit used for the current decoder configuration.
    ///
    /// Explicit limits, including `0` for no cap, take precedence over hints.
    #[inline]
    #[must_use]
    pub fn effective_max_buffer_len(&self) -> usize
    where
        D: Decoder,
    {
        if self.max_buffer_len_explicit {
            self.max_buffer_len
        } else {
            self.decoder
                .max_buffered_frame_len()
                .map_or(self.max_buffer_len, |hint| self.max_buffer_len.max(hint))
        }
    }

    /// Returns a reference to the underlying reader.
    #[inline]
    #[must_use]
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Returns a mutable reference to the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Returns a reference to the decoder.
    #[inline]
    #[must_use]
    pub fn decoder(&self) -> &D {
        &self.decoder
    }

    /// Returns a mutable reference to the decoder.
    pub fn decoder_mut(&mut self) -> &mut D {
        self.read_state = ReadState::NeedsDecode;
        &mut self.decoder
    }

    /// Returns a reference to the read buffer.
    #[inline]
    #[must_use]
    pub fn read_buffer(&self) -> &BytesMut {
        &self.buffer
    }

    /// Consumes `self` and returns the inner reader.
    #[inline]
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Consumes `self` and returns the inner reader, decoder, and buffer.
    pub fn into_parts(self) -> (R, D, BytesMut) {
        (self.inner, self.decoder, self.buffer)
    }
}

impl<R, D> Stream for FramedRead<R, D>
where
    R: AsyncRead + Unpin,
    D: Decoder + Unpin,
{
    type Item = Result<D::Item, D::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // br-asupersync-3asq77: once any error has been surfaced, the
        // stream is terminally poisoned. Re-polling must NOT re-emit
        // the same bytes through the decoder (which would re-produce
        // the same error in a tight infinite loop, hanging any caller
        // that uses `collect` / `for_each`). Returning `None` at this
        // gate is the safe fail-closed policy; decoder-level recovery
        // (e.g. `LengthDelimitedCodec`'s Skip state) is the right
        // place to advance past offending bytes when the codec
        // actually knows the framing.
        if this.poisoned {
            return Poll::Ready(None);
        }

        let mut read_passes = 0usize;
        let mut should_yield = false;

        loop {
            if !this.eof && this.read_state == ReadState::NeedsDecode {
                // Try to decode only when bytes or explicit decoder mutation
                // could have changed the previous result. EOF is handled by
                // decode_eof below without an unchanged ordinary retry.
                match this.decoder.decode(&mut this.buffer) {
                    Ok(Some(item)) => return Poll::Ready(Some(Ok(item))),
                    Ok(None) => {
                        this.read_state = ReadState::NeedsRead;
                        if should_yield {
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                    }
                    Err(e) => {
                        this.poisoned = true;
                        return Poll::Ready(Some(Err(e)));
                    }
                }
            }

            // If we hit EOF, give the decoder one last chance.
            if this.eof {
                return match this.decoder.decode_eof(&mut this.buffer) {
                    Ok(Some(item)) => {
                        // A decoder may emit more than one final frame. Keep
                        // decoding eligible so the next poll preserves the
                        // pre-EOF state-machine behavior even though no read
                        // can add bytes now.
                        this.read_state = ReadState::NeedsDecode;
                        Poll::Ready(Some(Ok(item)))
                    }
                    Ok(None) => Poll::Ready(None),
                    Err(e) => {
                        this.poisoned = true;
                        Poll::Ready(Some(Err(e)))
                    }
                };
            }

            // br-asupersync-yf1bg1: cap each ordinary read at the remaining
            // buffer capacity. This makes framing invariant to transport
            // batching: one read containing several legal frames can no
            // longer be rejected as though it were one oversized partial
            // frame. At exact capacity, offer a one-byte probe rather than a
            // zero-length ReadBuf: EOF must still reach decode_eof, IO errors
            // retain precedence, and a real extra byte takes the existing
            // over-cap error path below.
            let max_buffer_len = this.effective_max_buffer_len();
            let read_len = if max_buffer_len == 0 {
                READ_BUF_SIZE
            } else {
                max_buffer_len
                    .saturating_sub(this.buffer.len())
                    .clamp(1, READ_BUF_SIZE)
            };
            let mut tmp = [0u8; READ_BUF_SIZE];
            let mut read_buf = ReadBuf::new(&mut tmp[..read_len]);

            match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    this.poisoned = true;
                    return Poll::Ready(Some(Err(e.into())));
                }
                Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled();
                    if filled.is_empty() {
                        this.eof = true;
                        this.read_state = ReadState::NeedsDecode;
                        // Loop back to handle EOF decoding.
                    } else {
                        // br-asupersync-bj427s: bound the partial-frame
                        // buffer BEFORE appending. Without this check,
                        // a peer that streams bytes without ever
                        // closing a frame causes unbounded per-
                        // connection memory growth. The check is
                        // intentionally PRE-append so the buffer
                        // never crosses the cap; the caller observes
                        // the error before any over-the-cap memory is
                        // ever allocated. A max_buffer_len of 0
                        // disables enforcement.
                        if max_buffer_len > 0 {
                            let projected = this.buffer.len().saturating_add(filled.len());
                            if projected > max_buffer_len {
                                let cap = max_buffer_len;
                                let buffered = this.buffer.len();
                                let added = filled.len();
                                let err = io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!(
                                        "FramedRead buffer would exceed max_buffer_len: \
                                         {buffered} + {added} = {projected} > {cap} bytes \
                                         (slowloris-style partial-frame attack? \
                                         see br-asupersync-bj427s)"
                                    ),
                                );
                                this.poisoned = true;
                                return Poll::Ready(Some(Err(err.into())));
                            }
                        }
                        this.buffer.put_slice(filled);
                        this.read_state = ReadState::NeedsDecode;
                        read_passes += 1;
                        if read_passes >= MAX_READ_PASSES_PER_POLL {
                            should_yield = true;
                        }
                        // Loop back to try decoding.
                    }
                }
            }
        }
    }
}

impl<R: std::fmt::Debug, D: std::fmt::Debug> std::fmt::Debug for FramedRead<R, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FramedRead")
            .field("inner", &self.inner)
            .field("decoder", &self.decoder)
            .field("buffer_len", &self.buffer.len())
            .field("eof", &self.eof)
            .finish()
    }
}

#[cfg(test)]
#[path = "framed_read_inline_tests.rs"]
mod tests;
