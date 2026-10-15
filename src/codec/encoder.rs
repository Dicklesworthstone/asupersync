//! Encoder trait for framed transports.

use crate::bytes::BytesMut;
use std::io;

/// Encode items into bytes.
pub trait Encoder<Item> {
    /// Encoding error type.
    type Error: From<io::Error>;

    /// Encode an item into the buffer.
    fn encode(&mut self, item: Item, dst: &mut BytesMut) -> Result<(), Self::Error>;
}
