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
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Decoder for BytesCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>, io::Error> {
        if src.is_empty() {
            Ok(None)
        } else {
            let len = src.len();
            Ok(Some(src.split_to(len)))
        }
    }
}

impl Encoder<Bytes> for BytesCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), io::Error> {
        dst.reserve(item.len());
        dst.put_slice(&item);
        Ok(())
    }
}

impl Encoder<BytesMut> for BytesCodec {
    type Error = io::Error;

    fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<(), io::Error> {
        dst.reserve(item.len());
        dst.put_slice(&item);
        Ok(())
    }
}

impl Encoder<Vec<u8>> for BytesCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Vec<u8>, dst: &mut BytesMut) -> Result<(), io::Error> {
        dst.reserve(item.len());
        dst.put_slice(&item);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_returns_all_bytes() {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::from("hello");

        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(&frame[..], b"hello");
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_empty_returns_none() {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::new();

        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn encode_bytes() {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::new();
        let data = Bytes::from_static(b"world");

        codec.encode(data, &mut buf).unwrap();
        assert_eq!(&buf[..], b"world");
    }

    #[test]
    fn encode_bytes_mut() {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::new();
        let data = BytesMut::from("test");

        codec.encode(data, &mut buf).unwrap();
        assert_eq!(&buf[..], b"test");
    }

    #[test]
    fn encode_vec() {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::new();

        codec.encode(vec![1, 2, 3], &mut buf).unwrap();
        assert_eq!(&buf[..], &[1, 2, 3]);
    }

    // =========================================================================
    // Wave 45 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn bytes_codec_debug_clone_copy_default() {
        let codec = BytesCodec::default();
        let dbg = format!("{codec:?}");
        assert_eq!(dbg, "BytesCodec");
        let copied = codec;
        let cloned = codec.clone();
        assert_eq!(format!("{copied:?}"), format!("{cloned:?}"));
    }
}
