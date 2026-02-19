//! Codec for length-prefixed framing.

use crate::bytes::BytesMut;
use crate::codec::Decoder;
use std::io;

/// Codec for length-prefixed framing.
#[derive(Debug, Clone)]
pub struct LengthDelimitedCodec {
    builder: LengthDelimitedCodecBuilder,
    state: DecodeState,
}

/// Builder for `LengthDelimitedCodec`.
#[derive(Debug, Clone)]
pub struct LengthDelimitedCodecBuilder {
    length_field_offset: usize,
    length_field_length: usize,
    length_adjustment: isize,
    num_skip: usize,
    max_frame_length: usize,
    big_endian: bool,
}

#[derive(Debug, Clone, Copy)]
enum DecodeState {
    Head,
    Data(usize),
}

impl LengthDelimitedCodec {
    /// Creates a codec with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::builder().new_codec()
    }

    /// Returns a builder for configuring the codec.
    #[must_use]
    pub fn builder() -> LengthDelimitedCodecBuilder {
        LengthDelimitedCodecBuilder {
            length_field_offset: 0,
            length_field_length: 4,
            length_adjustment: 0,
            num_skip: 4,
            max_frame_length: 8 * 1024 * 1024,
            big_endian: true,
        }
    }
}

impl Default for LengthDelimitedCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl LengthDelimitedCodecBuilder {
    /// Sets the length field offset.
    #[must_use]
    pub fn length_field_offset(mut self, val: usize) -> Self {
        self.length_field_offset = val;
        self
    }

    /// Sets the length field length (1..=8 bytes).
    #[must_use]
    pub fn length_field_length(mut self, val: usize) -> Self {
        self.length_field_length = val;
        self
    }

    /// Adjusts the reported length by this amount.
    #[must_use]
    pub fn length_adjustment(mut self, val: isize) -> Self {
        self.length_adjustment = val;
        self
    }

    /// Number of bytes to skip before frame data.
    #[must_use]
    pub fn num_skip(mut self, val: usize) -> Self {
        self.num_skip = val;
        self
    }

    /// Sets the maximum frame length.
    #[must_use]
    pub fn max_frame_length(mut self, val: usize) -> Self {
        self.max_frame_length = val;
        self
    }

    /// Configures the codec to read lengths in big-endian order.
    #[must_use]
    pub fn big_endian(mut self) -> Self {
        self.big_endian = true;
        self
    }

    /// Configures the codec to read lengths in little-endian order.
    #[must_use]
    pub fn little_endian(mut self) -> Self {
        self.big_endian = false;
        self
    }

    /// Builds the codec.
    #[must_use]
    pub fn new_codec(self) -> LengthDelimitedCodec {
        assert!(
            (1..=8).contains(&self.length_field_length),
            "length_field_length must be 1..=8"
        );
        LengthDelimitedCodec {
            builder: self,
            state: DecodeState::Head,
        }
    }
}

impl LengthDelimitedCodec {
    fn decode_head(&self, src: &BytesMut) -> io::Result<u64> {
        let offset = self.builder.length_field_offset;
        let len = self.builder.length_field_length;
        let end = offset.saturating_add(len);

        if src.len() < end {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "not enough bytes for length field",
            ));
        }

        let bytes = &src[offset..end];
        let mut value: u64 = 0;
        if self.builder.big_endian {
            for &b in bytes {
                value = (value << 8) | u64::from(b);
            }
        } else {
            for (shift, &b) in bytes.iter().enumerate() {
                value |= u64::from(b) << (shift * 8);
            }
        }

        Ok(value)
    }

    fn adjusted_frame_len(&self, len: u64) -> io::Result<usize> {
        let len_i64 = i64::try_from(len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "length exceeds i64"))?;

        let adjustment = i64::try_from(self.builder.length_adjustment).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "length adjustment exceeds i64")
        })?;

        let adjusted = len_i64
            .checked_add(adjustment)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "length overflow"))?;

        if adjusted < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "negative frame length",
            ));
        }

        let len_usize = usize::try_from(adjusted)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "length exceeds usize"))?;

        if len_usize > self.builder.max_frame_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame length exceeds max_frame_length",
            ));
        }

        Ok(len_usize)
    }
}

impl Decoder for LengthDelimitedCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<BytesMut>> {
        loop {
            match self.state {
                DecodeState::Head => {
                    let header_len = self
                        .builder
                        .length_field_offset
                        .saturating_add(self.builder.length_field_length);

                    if src.len() < header_len {
                        return Ok(None);
                    }

                    let raw_len = self.decode_head(src)?;
                    let frame_len = self.adjusted_frame_len(raw_len)?;

                    if src.len() < self.builder.num_skip {
                        return Ok(None);
                    }

                    if self.builder.num_skip > 0 {
                        let _ = src.split_to(self.builder.num_skip);
                    }

                    self.state = DecodeState::Data(frame_len);
                }
                DecodeState::Data(frame_len) => {
                    if src.len() < frame_len {
                        return Ok(None);
                    }

                    let data = src.split_to(frame_len);
                    self.state = DecodeState::Head;
                    return Ok(Some(data));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::BytesMut;

    #[test]
    fn test_length_delimited_decode() {
        let mut codec = LengthDelimitedCodec::new();
        let mut buf = BytesMut::new();
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(5);
        buf.put_slice(b"hello");

        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(&frame[..], b"hello");
        assert!(buf.is_empty());
    }

    #[test]
    fn test_length_delimited_partial() {
        let mut codec = LengthDelimitedCodec::new();
        let mut buf = BytesMut::new();
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(5);
        buf.put_slice(b"he");

        assert!(codec.decode(&mut buf).unwrap().is_none());
        buf.put_slice(b"llo");
        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(&frame[..], b"hello");
    }

    #[test]
    fn test_length_delimited_adjustment() {
        let mut codec = LengthDelimitedCodec::builder()
            .length_adjustment(2)
            .num_skip(4)
            .new_codec();

        let mut buf = BytesMut::new();
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(3);
        buf.put_slice(b"hello");

        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(&frame[..], b"hello");
    }

    #[test]
    fn test_length_delimited_max_frame_length() {
        let mut codec = LengthDelimitedCodec::builder()
            .max_frame_length(4)
            .new_codec();

        let mut buf = BytesMut::new();
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(5);
        buf.put_slice(b"hello");

        let err = codec.decode(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    // Pure data-type tests (wave 15 – CyanBarn)

    #[test]
    fn codec_debug() {
        let codec = LengthDelimitedCodec::new();
        let dbg = format!("{codec:?}");
        assert!(dbg.contains("LengthDelimitedCodec"));
    }

    #[test]
    fn codec_clone() {
        let codec = LengthDelimitedCodec::builder()
            .max_frame_length(1024)
            .new_codec();
        let cloned = codec;
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("LengthDelimitedCodec"));
    }

    #[test]
    fn codec_default() {
        let codec = LengthDelimitedCodec::default();
        // Default max frame is 8MB.
        let dbg = format!("{codec:?}");
        assert!(dbg.contains("8388608"));
    }

    #[test]
    fn builder_debug() {
        let builder = LengthDelimitedCodec::builder();
        let dbg = format!("{builder:?}");
        assert!(dbg.contains("LengthDelimitedCodecBuilder"));
    }

    #[test]
    fn builder_clone() {
        let builder = LengthDelimitedCodec::builder().max_frame_length(512);
        let cloned = builder;
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("512"));
    }

    #[test]
    fn builder_all_setters() {
        let codec = LengthDelimitedCodec::builder()
            .length_field_offset(2)
            .length_field_length(2)
            .length_adjustment(-2)
            .num_skip(4)
            .max_frame_length(4096)
            .big_endian()
            .new_codec();

        let dbg = format!("{codec:?}");
        assert!(dbg.contains("4096"));
    }

    #[test]
    fn builder_little_endian_decode() {
        let mut codec = LengthDelimitedCodec::builder()
            .little_endian()
            .new_codec();

        let mut buf = BytesMut::new();
        // Little-endian length 3: [3, 0, 0, 0]
        buf.put_u8(3);
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_slice(b"abc");

        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(&frame[..], b"abc");
    }

    #[test]
    fn builder_length_field_length_2() {
        let mut codec = LengthDelimitedCodec::builder()
            .length_field_length(2)
            .num_skip(2)
            .new_codec();

        let mut buf = BytesMut::new();
        // Big-endian 2-byte length: 4
        buf.put_u8(0);
        buf.put_u8(4);
        buf.put_slice(b"data");

        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(&frame[..], b"data");
    }

    #[test]
    fn builder_length_field_offset() {
        let mut codec = LengthDelimitedCodec::builder()
            .length_field_offset(2)
            .num_skip(6)
            .new_codec();

        let mut buf = BytesMut::new();
        // 2 prefix bytes, then 4-byte big-endian length 3
        buf.put_u8(0xAA);
        buf.put_u8(0xBB);
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(3);
        buf.put_slice(b"xyz");

        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(&frame[..], b"xyz");
    }

    #[test]
    fn decode_empty_frame() {
        let mut codec = LengthDelimitedCodec::new();
        let mut buf = BytesMut::new();
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(0);

        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert!(frame.is_empty());
    }
}
