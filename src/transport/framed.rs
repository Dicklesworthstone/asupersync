//! Authenticated symbol delivery over an owned asynchronous byte stream.
//!
//! Each frame is a four-byte big-endian length followed by the existing
//! canonical `ASUPSYM` version-one batch encoding containing exactly one
//! symbol. This is the same authenticated symbol representation used by
//! [`crate::distributed::symbol_service`], with ordinary length-delimited
//! framing around it. No symbol flags or authentication decisions cross the
//! wire: the receiving key verifies every symbol again.
//!
//! The adapters work with TCP, TLS, Unix streams, and their owned read/write
//! halves. They do not dial, spawn a driver, negotiate object parameters, or
//! acknowledge remote delivery. The owner supplies the transport and runs its
//! cancellation/deadline policy around the symbol operations.

use super::{SinkError, StreamError, SymbolSink, SymbolStream};
use crate::bytes::BytesMut;
use crate::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use crate::distributed::symbol_service::{
    SymbolBatchLimits, SymbolStoreError, decode_symbol_batch, encode_symbol_batch,
};
use crate::io::{AsyncRead, AsyncWrite};
use crate::security::{AuthKey, AuthenticatedSymbol};
use crate::stream::Stream;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

// V1's fixed 32-byte batch header and 42-byte singleton entry header.
const SINGLE_SYMBOL_OVERHEAD: usize = 74;
const LENGTH_PREFIX: usize = 4;
const INITIAL_CAPACITY: usize = 8192;

/// Finite bounds for a single authenticated symbol and its enclosing frame.
///
/// The wire carries one symbol per frame. The bound applies to the symbol's
/// payload, independent of framing and authentication overhead. The reader
/// rejects oversized advertised lengths and never retains more than one
/// maximum wire frame; the writer admits at most one encoded frame before
/// requiring transport progress.
/// Allocator capacity, caller-owned symbols, and temporary bounded codec
/// copies are not included in the retained wire-byte limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolFrameLimits {
    max_symbol_bytes: usize,
    batch: SymbolBatchLimits,
    max_wire_bytes: usize,
}

impl SymbolFrameLimits {
    /// Construct explicit bounds. Zero, overflowing, and unrepresentable
    /// length-prefixed frames are rejected before a transport is acquired.
    pub fn new(max_symbol_bytes: usize) -> io::Result<Self> {
        let invalid = || {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid symbol frame payload limit")
        };
        if max_symbol_bytes == 0 {
            return Err(invalid());
        }
        let max_encoded_bytes = max_symbol_bytes
            .checked_add(SINGLE_SYMBOL_OVERHEAD)
            .ok_or_else(invalid)?;
        let max_wire_bytes = max_encoded_bytes.checked_add(LENGTH_PREFIX).ok_or_else(invalid)?;
        let max_decoded_bytes = max_symbol_bytes
            .checked_add(std::mem::size_of::<AuthenticatedSymbol>())
            .ok_or_else(invalid)?;
        if u32::try_from(max_encoded_bytes).is_err()
            || isize::try_from(max_wire_bytes).is_err()
            || isize::try_from(max_decoded_bytes).is_err()
        {
            return Err(invalid());
        }
        Ok(Self {
            max_symbol_bytes,
            batch: SymbolBatchLimits {
                max_encoded_bytes,
                max_symbols: 1,
                max_payload_bytes: max_symbol_bytes,
                max_decoded_bytes,
            },
            max_wire_bytes,
        })
    }

    /// Maximum symbol payload length.
    #[must_use]
    pub const fn max_symbol_bytes(self) -> usize { self.max_symbol_bytes }

    /// Maximum complete wire frame, including length and canonical headers.
    #[must_use]
    pub const fn max_wire_bytes(self) -> usize { self.max_wire_bytes }

    pub(super) const fn batch_limits(self) -> SymbolBatchLimits {
        self.batch
    }

    fn codec(self) -> LengthDelimitedCodec {
        LengthDelimitedCodec::builder()
            .max_frame_length(self.batch.max_encoded_bytes)
            .new_codec()
    }
}

impl Default for SymbolFrameLimits {
    /// Allow a symbol payload up to 64 KiB.
    fn default() -> Self {
        Self::new(64 * 1024).expect("the default symbol frame limit is representable")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SinkState {
    Open,
    Closing,
    Closed,
    Failed,
}

/// A bounded [`SymbolSink`] over an asynchronous writer.
///
/// `poll_send(Ready(Ok(())))` means one complete frame was accepted into this
/// adapter. It does not mean the peer received or decoded the symbol.
/// `poll_flush` finishes all retained bytes and flushes the underlying writer;
/// it is a local transport operation, not a remote acknowledgement.
///
/// Pending readiness, flush, or close operations retain their exact write
/// cursor in the adapter. Dropping a borrowing wait and retrying it does not
/// replay a frame prefix. A pending send has not accepted its argument, as
/// required by [`SymbolSink`]. Once close begins no new symbol is accepted;
/// close drains the accepted frame and shuts down only the supplied writer.
/// For a duplex connection use an owned write half to preserve the read half.
///
/// Zero-tag unauthenticated symbols are refused. Other tags are transported
/// unchanged and must pass the receiver's explicit key; a sender-side
/// `is_verified` flag is never used as authority. Transport errors poison the
/// sink, preventing a partially written frame from being followed by new data.
/// A caught panic from the underlying writer also leaves the sink failed:
/// bytes accepted before that panic cannot safely be replayed.
pub struct FramedSymbolSink<W> {
    framed: FramedWrite<W, LengthDelimitedCodec>,
    limits: SymbolFrameLimits,
    state: SinkState,
}

impl<W> FramedSymbolSink<W> {
    /// Wrap an owned writer without opening a connection or writing any bytes.
    #[must_use]
    pub fn new(writer: W, limits: SymbolFrameLimits) -> Self {
        Self {
            framed: FramedWrite::with_capacity(
                writer, limits.codec(), limits.max_wire_bytes.min(INITIAL_CAPACITY),
            ).with_backpressure_boundary(1),
            limits,
            state: SinkState::Open,
        }
    }

    /// The immutable per-frame bounds.
    #[must_use]
    pub const fn limits(&self) -> SymbolFrameLimits { self.limits }

    /// Inspect the transport without bypassing its retained frame cursor.
    #[must_use]
    pub fn get_ref(&self) -> &W { self.framed.get_ref() }

    /// Bytes of the accepted frame that have not yet reached the transport.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize { self.framed.write_buffer().len() }
}

impl<W: AsyncWrite + Unpin> FramedSymbolSink<W> {
    fn ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        if self.state != SinkState::Open {
            return Poll::Ready(Err(SinkError::Closed));
        }
        self.state = SinkState::Failed;
        match self.framed.poll_ready(cx) {
            Poll::Ready(Err(error)) => {
                Poll::Ready(Err(error.into()))
            }
            other => {
                self.state = SinkState::Open;
                other.map_err(Into::into)
            }
        }
    }
}

impl<W: AsyncWrite + Send + Unpin> SymbolSink for FramedSymbolSink<W> {
    fn poll_send(
        self: Pin<&mut Self>, cx: &mut Context<'_>, symbol: AuthenticatedSymbol,
    ) -> Poll<Result<(), SinkError>> {
        let this = self.get_mut();
        if this.state != SinkState::Open {
            return Poll::Ready(Err(SinkError::Closed));
        }
        // Reject the new argument before progressing an already accepted frame.
        // These local admission errors leave the established sink usable.
        if symbol.tag().is_zero() {
            return Poll::Ready(Err(SinkError::SendFailed {
                reason: "authenticated symbol tag required".to_owned(),
            }));
        }
        if symbol.symbol().data().len() > this.limits.max_symbol_bytes {
            return Poll::Ready(Err(SinkError::SendFailed {
                reason: "symbol payload exceeds frame limit".to_owned(),
            }));
        }
        match this.ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        let encoded = match encode_symbol_batch(std::slice::from_ref(&symbol), this.limits.batch_limits()) {
            Ok(encoded) => encoded,
            Err(error) => return Poll::Ready(Err(SinkError::SendFailed { reason: error.to_string() })),
        };
        // All acceptance is synchronous. Returning Pending after this point
        // would let SymbolSinkExt retry the argument and duplicate the symbol.
        match this.framed.start_send(BytesMut::from(encoded.as_ref())) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(error) => {
                this.state = SinkState::Failed;
                Poll::Ready(Err(error.into()))
            }
        }
    }

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        self.get_mut().ready(cx)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        let this = self.get_mut();
        match this.state {
            SinkState::Closed => return Poll::Ready(Ok(())),
            SinkState::Failed => return Poll::Ready(Err(SinkError::Closed)),
            SinkState::Open | SinkState::Closing => {}
        }
        let previous = this.state;
        this.state = SinkState::Failed;
        match this.framed.poll_flush(cx) {
            Poll::Ready(Err(error)) => {
                Poll::Ready(Err(error.into()))
            }
            other => {
                this.state = previous;
                other.map_err(Into::into)
            }
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        let this = self.get_mut();
        match this.state {
            SinkState::Closed => return Poll::Ready(Ok(())),
            SinkState::Failed => return Poll::Ready(Err(SinkError::Closed)),
            SinkState::Open => this.state = SinkState::Closing,
            SinkState::Closing => {}
        }
        this.state = SinkState::Failed;
        match this.framed.poll_close(cx) {
            Poll::Pending => {
                this.state = SinkState::Closing;
                Poll::Pending
            }
            Poll::Ready(Ok(())) => {
                this.state = SinkState::Closed;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                this.state = SinkState::Failed;
                Poll::Ready(Err(error.into()))
            }
        }
    }
}

impl<W> fmt::Debug for FramedSymbolSink<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FramedSymbolSink")
            .field("limits", &self.limits)
            .field("state", &self.state)
            .field("buffered_bytes", &self.buffered_bytes())
            .finish_non_exhaustive()
    }
}

/// A bounded [`SymbolStream`] that verifies every received symbol.
///
/// The explicit receiver key authenticates the canonical symbol identity,
/// kind, length, and payload. The frame must contain exactly one symbol;
/// unauthenticated sentinel tags and incorrect tags are refused. Authentication,
/// framing, truncation, and transport errors are yielded once and permanently
/// terminate the stream. A caught reader panic also terminates it because the
/// consumed byte count is unknown. EOF between complete frames is a normal end
/// of input.
///
/// Partial frame bytes live in this adapter, so dropping a pending borrowing
/// receive and retrying it preserves progress. Read buffering is capped at one
/// maximum wire frame. Existing framed I/O also bounds repeated ready reads
/// per poll; a genuinely pending reader is responsible for readiness wakes.
pub struct FramedSymbolStream<R> {
    framed: FramedRead<R, LengthDelimitedCodec>,
    key: AuthKey,
    limits: SymbolFrameLimits,
    ended: bool,
}

impl<R> FramedSymbolStream<R> {
    /// Wrap an owned reader with the key trusted to authenticate its symbols.
    #[must_use]
    pub fn new(reader: R, key: AuthKey, limits: SymbolFrameLimits) -> Self {
        Self {
            framed: FramedRead::with_capacity(
                reader, limits.codec(), limits.max_wire_bytes.min(INITIAL_CAPACITY),
            ).with_max_buffer_len(limits.max_wire_bytes),
            key,
            limits,
            ended: false,
        }
    }

    /// The immutable per-frame bounds.
    #[must_use]
    pub const fn limits(&self) -> SymbolFrameLimits { self.limits }

    /// Inspect the transport without consuming retained frame bytes.
    #[must_use]
    pub fn get_ref(&self) -> &R { self.framed.get_ref() }

    /// Wire bytes retained while waiting for a complete frame.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize { self.framed.read_buffer().len() }
}

impl<R: AsyncRead + Send + Unpin> SymbolStream for FramedSymbolStream<R> {
    fn poll_next(
        self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(None);
        }
        this.ended = true;
        let bytes = match Stream::poll_next(Pin::new(&mut this.framed), cx) {
            Poll::Pending => {
                this.ended = false;
                return Poll::Pending;
            }
            Poll::Ready(None) => {
                this.ended = true;
                return Poll::Ready(None);
            }
            Poll::Ready(Some(Err(error))) => {
                this.ended = true;
                return Poll::Ready(Some(Err(error.into())));
            }
            Poll::Ready(Some(Ok(bytes))) => bytes,
        };
        match decode_symbol_batch(&bytes, &this.key, this.limits.batch_limits()) {
            Ok(mut symbols) => {
                let symbol = symbols.pop().expect("singleton batch admitted");
                this.ended = false;
                Poll::Ready(Some(Ok(symbol)))
            }
            Err(error) => {
                this.ended = true;
                let error = if error == SymbolStoreError::Authentication {
                    StreamError::AuthenticationFailed { reason: error.to_string() }
                } else {
                    StreamError::ProtocolError { details: error.to_string() }
                };
                Poll::Ready(Some(Err(error)))
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.ended { (0, Some(0)) } else { (0, None) }
    }

    fn is_exhausted(&self) -> bool { self.ended }
}

impl<R> fmt::Debug for FramedSymbolStream<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FramedSymbolStream")
            .field("limits", &self.limits)
            .field("ended", &self.ended)
            .field("buffered_bytes", &self.buffered_bytes())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[path = "framed/tests.rs"]
mod tests;
