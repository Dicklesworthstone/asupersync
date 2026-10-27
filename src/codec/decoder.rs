//! Decoder trait for framed transports.

use crate::bytes::BytesMut;
use std::io;

/// Decode bytes into frames.
pub trait Decoder {
    /// Type of decoded frames.
    type Item;
    /// Decoding error type.
    type Error: From<io::Error>;

    /// Attempt to decode a frame from the buffer.
    ///
    /// Returns:
    /// - `Ok(Some(item))` when a full frame is available
    /// - `Ok(None)` when more data is needed
    /// - `Err(e)` on decode errors
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error>;

    /// Maximum input-buffer length needed for one permitted encoded frame.
    ///
    /// This includes any length prefix, offset bytes, retained headers, and
    /// delimiter that must be buffered before [`Self::decode`] can emit the
    /// frame. It is a bound derived from the decoder's local configuration,
    /// not a minimum read size or a length supplied by an untrusted peer.
    /// Implementations must not enlarge it in response to an incoming frame's
    /// advertised length. Decoder-owned allocations are outside this bound.
    ///
    /// [`FramedRead`](crate::codec::FramedRead) and
    /// [`Framed`](crate::codec::Framed) use a finite hint to enlarge their
    /// default read-buffer limit when necessary. An explicit
    /// `with_max_buffer_len` remains authoritative, even if it is smaller than
    /// this hint. The hint is queried before reads, so changing a decoder's
    /// configuration through its mutable accessor updates the automatic limit.
    ///
    /// `None` means unknown, unbounded, or unrepresentable; it preserves the
    /// framed transport's bounded default rather than disabling enforcement.
    /// The provided implementation preserves existing decoder implementations.
    fn max_buffered_frame_len(&self) -> Option<usize> {
        None
    }

    /// Called when EOF is reached.
    ///
    /// Framed transports call this repeatedly after each `Ok(Some(item))`
    /// until it returns `Ok(None)` or an error. Once EOF is observed, they do
    /// not interpose a separate call to [`Self::decode`] between these calls.
    /// Implementations that emit multiple final frames must advance their
    /// buffered or internal state on each call and eventually return
    /// `Ok(None)`.
    ///
    /// By default, this attempts one last decode and then errors if any
    /// bytes remain but no full frame can be produced.
    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.decode(src)? {
            Some(frame) => Ok(Some(frame)),
            None if src.is_empty() => Ok(None),
            None => {
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete frame at EOF").into())
            }
        }
    }
}
