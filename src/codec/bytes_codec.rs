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

impl Encoder<Bytes> for BytesCodec {
    type Error = io::Error;

    #[inline]
    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), io::Error> {
        dst.reserve(item.len());
        dst.put_slice(&item);
        Ok(())
    }
}

impl Encoder<BytesMut> for BytesCodec {
    type Error = io::Error;

    #[inline]
    fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<(), io::Error> {
        dst.reserve(item.len());
        dst.put_slice(&item);
        Ok(())
    }
}

impl Encoder<Vec<u8>> for BytesCodec {
    type Error = io::Error;

    #[inline]
    fn encode(&mut self, item: Vec<u8>, dst: &mut BytesMut) -> Result<(), io::Error> {
        dst.reserve(item.len());
        dst.put_slice(&item);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
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
        let codec = BytesCodec;
        let dbg = format!("{codec:?}");
        assert_eq!(dbg, "BytesCodec");
        let copied = codec;
        let cloned = codec;
        assert_eq!(format!("{copied:?}"), format!("{cloned:?}"));
    }

    /// MR: arbitrary-binary round-trip (br-asupersync-rsnz1h)
    ///
    /// Property: for ANY &[u8] payload (empty, all-0, all-0xFF, random
    /// binary, embedded NULs, embedded UTF-8 BOM, embedded CRLF), encode
    /// then decode MUST yield byte-equal payload.
    ///
    /// The bytes_codec is a 1:1 byte-passthrough so this property is
    /// trivial today, but any future framing addition (NUL escaping,
    /// length-prefixing, base64 transport encoding) could regress it
    /// silently. This test locks the invariant.
    ///
    /// Catches: silent semantic drift (decode returns DIFFERENT bytes,
    /// not just a panic — fuzz catches panics; metamorphic catches
    /// drift). Drift here propagates to every downstream codec layer.
    #[test]
    fn mr_arbitrary_binary_round_trip() {
        // Curated edge-case payloads that cover the documented danger
        // patterns even without a property-test framework dependency.
        let edge_cases: Vec<Vec<u8>> = vec![
            // Empty.
            vec![],
            // Single byte: every value 0..=255.
            (0u8..=255).map(|b| vec![b]).collect::<Vec<_>>().concat(),
            // All zeros (4 KiB).
            vec![0x00u8; 4096],
            // All 0xFF (4 KiB).
            vec![0xFFu8; 4096],
            // Embedded NULs.
            b"hello\0world\0\0\0".to_vec(),
            // Embedded UTF-8 BOM + CRLF.
            b"\xEF\xBB\xBFheader\r\nbody\r\n".to_vec(),
            // Full byte range as a single 256-byte payload.
            (0u8..=255).collect::<Vec<u8>>(),
            // Non-trivial random-looking binary.
            (0u16..1024).flat_map(|i| {
                let n = (i.wrapping_mul(0x9E37) ^ i) as u8;
                std::iter::repeat(n).take(((n % 7) + 1) as usize)
            }).collect::<Vec<_>>(),
        ];

        for (i, payload) in edge_cases.iter().enumerate() {
            let mut codec = BytesCodec::new();
            let mut buf = BytesMut::new();
            codec
                .encode(Bytes::copy_from_slice(payload), &mut buf)
                .unwrap_or_else(|e| panic!("encode case {i} failed: {e}"));
            // BytesCodec amplification is identity (no header).
            assert_eq!(
                buf.len(),
                payload.len(),
                "case {i}: BytesCodec must be 1:1 (no framing overhead)"
            );
            let decoded_opt = codec
                .decode(&mut buf)
                .unwrap_or_else(|e| panic!("decode case {i} failed: {e}"));
            let decoded_bytes: Vec<u8> = match decoded_opt {
                Some(b) => b.to_vec(),
                None => {
                    if payload.is_empty() {
                        // Empty input: codec may yield None — also acceptable.
                        Vec::new()
                    } else {
                        panic!("decode case {i} yielded None for non-empty payload")
                    }
                }
            };
            assert_eq!(
                decoded_bytes,
                *payload,
                "case {i}: round-trip drift — payload {} bytes, decoded {} bytes",
                payload.len(),
                decoded_bytes.len()
            );
        }
    }
}
