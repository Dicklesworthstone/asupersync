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

    /// Called when EOF is reached.
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
