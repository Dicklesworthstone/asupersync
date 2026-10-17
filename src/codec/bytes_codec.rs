//! Raw bytes pass-through codec.

use crate::bytes::{Bytes, BytesMut};
use crate::codec::{Decoder, Encoder};
use std::io;

/// Codec that passes raw bytes through without framing.
///
/// Decoding yields all available bytes in the buffer. Encoding copies
/// the input bytes directly into the output buffer.
#[derive(Debug, Clone, Copy, Default)]
pub struct BytesCodec;

impl BytesCodec {
    /// Creates a new `BytesCodec`.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Decoder for BytesCodec {
    type Item = BytesMut;
    type Error = io::Error;

    #[inline]
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>, io::Error> {
        if src.is_empty() {
            Ok(None)
        } else {
            let len = src.len();
            Ok(Some(src.split_to(len)))
        }
    }
}

macro_rules! impl_bytes_encoder {
    ($($item:ty),+ $(,)?) => {
        $(
            impl Encoder<$item> for BytesCodec {
                type Error = io::Error;

                #[inline]
                fn encode(&mut self, item: $item, dst: &mut BytesMut) -> Result<(), io::Error> {
                    dst.reserve(item.len());
                    dst.put_slice(&item);
                    Ok(())
                }
            }
        )+
    };
}

impl_bytes_encoder!(Bytes, BytesMut, Vec<u8>);

#[cfg(test)]
#[path = "bytes_codec_inline_tests.rs"]
mod tests;
