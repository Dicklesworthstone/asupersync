#![allow(clippy::cast_possible_wrap)]
//! Codec for length-prefixed framing.

use crate::bytes::{BufMut, BytesMut};
use crate::codec::{Decoder, Encoder};
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
    /// Discarding the remaining bytes of an over-sized frame (or any
    /// frame whose adjusted length failed validation post-header). The
    /// counter is the number of bytes still to drain before the codec
    /// can attempt to decode the next frame's header.
    ///
    /// br-asupersync-o7e5xu: previously, when `adjusted_frame_len`
    /// returned `Err(frame length exceeds max_frame_length)`, the `?`
    /// propagated WITHOUT consuming the length-prefix bytes. The next
    /// `decode()` call read the same bytes, computed the same too-large
    /// length, returned the same `Err` — infinite re-emission per
    /// poll. The Skip state is the framing-recovery counter: once we
    /// detect a bad length we consume the header + skip the body
    /// across however many `decode()` calls it takes for the body to
    /// arrive on the wire, then resume normal decoding.
    ///
    /// `u64` (not `usize`) because the offending advertised length can
    /// be near `u64::MAX` on a 64-bit target while we only buffer
    /// `usize::MAX` bytes per call — the counter must outlive the
    /// in-buffer suffix.
    Skip(u64),
}

fn max_length_field_value(length_field_length: usize) -> io::Result<u64> {
    match length_field_length {
        1..=7 => Ok((1u64 << (length_field_length * 8)) - 1),
        8 => Ok(u64::MAX),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid length_field_length",
        )),
    }
}

impl LengthDelimitedCodec {
    /// Creates a codec with default settings.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::builder().new_codec()
    }

    /// Returns a builder for configuring the codec.
    #[inline]
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
    #[inline]
    #[must_use]
    pub fn length_field_offset(mut self, val: usize) -> Self {
        self.length_field_offset = val;
        self
    }

    /// Sets the length field length (1..=8 bytes).
    #[inline]
    #[must_use]
    pub fn length_field_length(mut self, val: usize) -> Self {
        self.length_field_length = val;
        self
    }

    /// Adjusts the reported length by this amount.
    #[inline]
    #[must_use]
    pub fn length_adjustment(mut self, val: isize) -> Self {
        self.length_adjustment = val;
        self
    }

    /// Number of bytes to skip before frame data.
    #[inline]
    #[must_use]
    pub fn num_skip(mut self, val: usize) -> Self {
        self.num_skip = val;
        self
    }

    /// Sets the maximum frame length.
    #[inline]
    #[must_use]
    pub fn max_frame_length(mut self, val: usize) -> Self {
        self.max_frame_length = val;
        self
    }

    /// Configures the codec to read lengths in big-endian order.
    #[inline]
    #[must_use]
    pub fn big_endian(mut self) -> Self {
        self.big_endian = true;
        self
    }

    /// Configures the codec to read lengths in little-endian order.
    #[inline]
    #[must_use]
    pub fn little_endian(mut self) -> Self {
        self.big_endian = false;
        self
    }

    /// Builds the codec.
    #[inline]
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
                    let frame_len = match self.adjusted_frame_len(raw_len) {
                        Ok(n) => n,
                        Err(e) => {
                            // br-asupersync-o7e5xu: framing recovery on
                            // any post-header length validation failure
                            // (max_frame_length exceeded, negative
                            // adjustment, length overflow, etc).
                            //
                            // Without this branch, the `?` shortcut would
                            // propagate `e` while leaving `src` untouched.
                            // The next decode() call would re-read the
                            // same length bytes and re-emit the same Err
                            // — an infinite loop on the caller's poll.
                            //
                            // Consume the header bytes from the buffer
                            // and transition to Skip state with a counter
                            // sized to drain the offending frame's body
                            // across however many decode() calls it
                            // takes for the body to arrive on the wire.
                            // The body skip-count is the RAW length
                            // (pre-adjustment) because that's what the
                            // peer claims to have written — adjustment
                            // is a length-field semantic, not a wire
                            // count. Saturate to u64::MAX defensively
                            // if the raw length is somehow nonsense.
                            let _ = src.split_to(header_len);
                            self.state = DecodeState::Skip(raw_len);
                            return Err(e);
                        }
                    };
                    let total_frame_len = header_len.checked_add(frame_len).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "frame length overflow")
                    })?;
                    let retained_len = total_frame_len
                        .checked_sub(self.builder.num_skip)
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "num_skip exceeds total frame length",
                            )
                        })?;

                    if src.len() < self.builder.num_skip {
                        return Ok(None);
                    }

                    if self.builder.num_skip > 0 {
                        let _ = src.split_to(self.builder.num_skip);
                    }

                    // The decoder must wait for the bytes still visible after
                    // applying `num_skip`, not just the payload length. When
                    // callers retain some header bytes (`num_skip < header_len`),
                    // those retained prefix bytes are part of the returned frame.
                    self.state = DecodeState::Data(retained_len);
                }
                DecodeState::Data(frame_len) => {
                    if src.len() < frame_len {
                        return Ok(None);
                    }

                    let data = src.split_to(frame_len);
                    self.state = DecodeState::Head;
                    return Ok(Some(data));
                }
                DecodeState::Skip(remaining) => {
                    // br-asupersync-o7e5xu: drain up to `remaining` bytes
                    // from src; the offending body may span many decode()
                    // calls. Once 0, transition back to Head and resume
                    // normal decoding on the next iteration of the loop
                    // (so a subsequent next-frame header in the same
                    // buffer is processed without an extra poll).
                    let avail = src.len() as u64;
                    let drain = remaining.min(avail);
                    if drain > 0 {
                        // `drain` is bounded by `avail` (a usize) so this
                        // try_from cannot fail; use as_usize via try_from
                        // for explicitness.
                        let drain_usize = usize::try_from(drain).unwrap_or(usize::MAX);
                        let _ = src.split_to(drain_usize);
                    }
                    let new_remaining = remaining - drain;
                    if new_remaining == 0 {
                        self.state = DecodeState::Head;
                        // Continue the loop — there may be a fresh
                        // header already buffered.
                        continue;
                    }
                    self.state = DecodeState::Skip(new_remaining);
                    return Ok(None);
                }
            }
        }
    }
}

impl Encoder<BytesMut> for LengthDelimitedCodec {
    type Error = io::Error;

    fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let frame_len = item.len();

        // Calculate the adjusted length to write in the length field
        let adjustment = i64::try_from(self.builder.length_adjustment).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "length adjustment exceeds i64")
        })?;

        let frame_len_i64 = i64::try_from(frame_len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame length exceeds i64"))?;

        let adjusted_len = frame_len_i64
            .checked_sub(adjustment)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "length underflow"))?;

        if adjusted_len < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "negative encoded length",
            ));
        }

        let length_to_encode = u64::try_from(adjusted_len).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "encoded length exceeds u64")
        })?;

        let max_length_value = max_length_field_value(self.builder.length_field_length)?;
        if length_to_encode > max_length_value {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "encoded length exceeds length_field_length capacity",
            ));
        }

        // Check max frame length limit
        if frame_len > self.builder.max_frame_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame length exceeds max_frame_length",
            ));
        }

        // br-asupersync-ooqkxe — checked arithmetic on the reserve budget.
        // The previous shape was `header_len + frame_len` after `header_len`
        // was computed via saturating_add — so an attacker-controlled
        // `length_field_offset` near `usize::MAX` could saturate and then
        // the unchecked `+ frame_len` would wrap, calling reserve() with a
        // tiny value and silently leaving the buffer too small for the
        // bytes we are about to put_u8/put_slice. checked_add(frame_len)
        // returns None on overflow; we surface that as InvalidData so
        // callers see an explicit error rather than a panic or buffer
        // corruption.
        let header_len = self
            .builder
            .length_field_offset
            .checked_add(self.builder.length_field_length)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "header length (offset + length_field_length) overflows usize",
                )
            })?;
        let total_len = header_len.checked_add(frame_len).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "frame buffer reservation overflows usize",
            )
        })?;

        // Reserve space for the entire frame
        dst.reserve(total_len);

        // Write length field offset padding (zeros)
        for _ in 0..self.builder.length_field_offset {
            dst.put_u8(0);
        }

        // Write the length field in the configured byte order
        if self.builder.big_endian {
            match self.builder.length_field_length {
                1 => dst.put_u8(length_to_encode as u8),
                2 => dst.put_u16(length_to_encode as u16),
                3 => {
                    dst.put_u8((length_to_encode >> 16) as u8);
                    dst.put_u16(length_to_encode as u16);
                }
                4 => dst.put_u32(length_to_encode as u32),
                5 => {
                    dst.put_u8((length_to_encode >> 32) as u8);
                    dst.put_u32(length_to_encode as u32);
                }
                6 => {
                    dst.put_u16((length_to_encode >> 32) as u16);
                    dst.put_u32(length_to_encode as u32);
                }
                7 => {
                    dst.put_u8((length_to_encode >> 48) as u8);
                    dst.put_u16((length_to_encode >> 32) as u16);
                    dst.put_u32(length_to_encode as u32);
                }
                8 => dst.put_u64(length_to_encode),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid length_field_length",
                    ));
                }
            }
        } else {
            // Little-endian encoding
            match self.builder.length_field_length {
                1 => dst.put_u8(length_to_encode as u8),
                2 => dst.put_u16_le(length_to_encode as u16),
                3 => {
                    dst.put_u16_le(length_to_encode as u16);
                    dst.put_u8((length_to_encode >> 16) as u8);
                }
                4 => dst.put_u32_le(length_to_encode as u32),
                5 => {
                    dst.put_u32_le(length_to_encode as u32);
                    dst.put_u8((length_to_encode >> 32) as u8);
                }
                6 => {
                    dst.put_u32_le(length_to_encode as u32);
                    dst.put_u16_le((length_to_encode >> 32) as u16);
                }
                7 => {
                    dst.put_u32_le(length_to_encode as u32);
                    dst.put_u16_le((length_to_encode >> 32) as u16);
                    dst.put_u8((length_to_encode >> 48) as u8);
                }
                8 => dst.put_u64_le(length_to_encode),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid length_field_length",
                    ));
                }
            }
        }

        // Write the frame data
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

    // ─── br-asupersync-o7e5xu: framing-recovery regression tests ────────

    /// The decoder MUST advance past the offending header on a
    /// max_frame_length violation. Without the fix, repeated decode()
    /// calls re-emit the same Err forever (infinite loop on the
    /// caller's poll).
    #[test]
    fn o7e5xu_max_frame_length_consumes_header_then_skips_body() {
        let mut codec = LengthDelimitedCodec::builder()
            .max_frame_length(4)
            .new_codec();

        let mut buf = BytesMut::new();
        // Frame 1: oversized (length=5, max=4). 4-byte header + 5-byte body.
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(5);
        buf.put_slice(b"hello");
        // Frame 2: well-formed (length=3, body=b"abc").
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(3);
        buf.put_slice(b"abc");

        // First call: returns the max-frame-length error AND consumes
        // the offending header + transitions to Skip state.
        let err = codec.decode(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // Second call: drains the over-sized body (5 bytes), transitions
        // back to Head, and immediately decodes the next well-formed
        // frame in the same loop iteration.
        let frame = codec
            .decode(&mut buf)
            .expect("decode must not error")
            .expect("frame ready");
        assert_eq!(frame.as_ref(), b"abc");

        // Buffer is fully drained.
        assert_eq!(buf.len(), 0);
    }

    /// Repeated polls after a max-frame-length error MUST NOT re-emit
    /// the same Err — they must drain the offending body and then
    /// either need-more-bytes or yield the next frame.
    #[test]
    fn o7e5xu_repeat_poll_does_not_reemit_max_frame_error() {
        let mut codec = LengthDelimitedCodec::builder()
            .max_frame_length(4)
            .new_codec();

        let mut buf = BytesMut::new();
        // Single oversized frame; no follow-on data.
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(5);
        buf.put_slice(b"hello");

        // First call: error.
        let err = codec.decode(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // Second and subsequent calls: NEVER again the same Err.
        // The body got drained on the second call (5 bytes available,
        // 5 to skip → Skip(0) → Head). Buffer is empty so the third
        // call returns Ok(None).
        let _drained = codec.decode(&mut buf).expect("must not Err on second poll");
        let third = codec.decode(&mut buf).expect("must not Err on third poll");
        assert!(third.is_none(), "buffer is empty, must yield Ok(None)");
    }

    /// The Skip state must persist across decode() calls when the
    /// offending body arrives in chunks (the realistic IO pattern).
    #[test]
    fn o7e5xu_skip_state_persists_across_chunked_body_arrival() {
        let mut codec = LengthDelimitedCodec::builder()
            .max_frame_length(2)
            .new_codec();

        // Header advertises 7 bytes; max is 2.
        let mut buf = BytesMut::new();
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(7);
        // Body chunk 1: 3 of 7 bytes.
        buf.put_slice(b"abc");

        // First call: Err + transition to Skip(7).
        let err = codec.decode(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // Second call: drains the 3 bytes available; remaining = 4.
        let r = codec.decode(&mut buf).expect("must not Err");
        assert!(r.is_none(), "still skipping");
        assert_eq!(buf.len(), 0);

        // Body chunk 2: 4 more bytes arrive.
        buf.put_slice(b"defg");

        // Third call: drains the 4 bytes; Skip(0) → Head; buffer empty.
        let r = codec.decode(&mut buf).expect("must not Err");
        assert!(r.is_none(), "skip complete, no next frame yet");

        // Now a fresh frame arrives.
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(2);
        buf.put_slice(b"OK");

        let frame = codec.decode(&mut buf).expect("decode").expect("frame");
        assert_eq!(frame.as_ref(), b"OK");
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
        let mut codec = LengthDelimitedCodec::builder().little_endian().new_codec();

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
    fn builder_num_skip_zero_retains_entire_header_and_keeps_alignment() {
        let mut codec = LengthDelimitedCodec::builder().num_skip(0).new_codec();

        let mut buf = BytesMut::new();
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(1);
        buf.put_slice(b"a");
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(1);
        buf.put_slice(b"b");

        let frame1 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(&frame1[..], &[0, 0, 0, 1, b'a']);

        let frame2 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(&frame2[..], &[0, 0, 0, 1, b'b']);
        assert!(buf.is_empty());
    }

    #[test]
    fn builder_partial_header_retention_returns_remaining_prefix_bytes() {
        let mut codec = LengthDelimitedCodec::builder().num_skip(2).new_codec();

        let mut buf = BytesMut::new();
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(3);
        buf.put_slice(b"hey");

        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(&frame[..], &[0, 3, b'h', b'e', b'y']);
        assert!(buf.is_empty());
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

    #[test]
    fn length_delimited_codec_debug_clone() {
        let codec = LengthDelimitedCodec::new();
        let cloned = codec.clone();
        let dbg = format!("{codec:?}");
        assert!(dbg.contains("LengthDelimitedCodec"));
        let dbg2 = format!("{cloned:?}");
        assert_eq!(dbg, dbg2);
    }

    #[test]
    fn length_delimited_codec_builder_debug_clone() {
        let builder = LengthDelimitedCodec::builder();
        let cloned = builder.clone();
        let dbg = format!("{builder:?}");
        assert!(dbg.contains("LengthDelimitedCodecBuilder"));
        let dbg2 = format!("{cloned:?}");
        assert_eq!(dbg, dbg2);
    }

    // Encoder tests
    #[test]
    fn test_encode_basic() {
        let mut codec = LengthDelimitedCodec::new();
        let mut dst = BytesMut::new();
        let data = BytesMut::from("hello");

        codec.encode(data, &mut dst).unwrap();

        // Should produce [0, 0, 0, 5, 'h', 'e', 'l', 'l', 'o']
        assert_eq!(dst.len(), 9);
        assert_eq!(&dst[0..4], &[0, 0, 0, 5]);
        assert_eq!(&dst[4..9], b"hello");
    }

    #[test]
    fn test_encode_little_endian() {
        let mut codec = LengthDelimitedCodec::builder().little_endian().new_codec();
        let mut dst = BytesMut::new();
        let data = BytesMut::from("hi");

        codec.encode(data, &mut dst).unwrap();

        // Should produce [2, 0, 0, 0, 'h', 'i'] in little-endian
        assert_eq!(dst.len(), 6);
        assert_eq!(&dst[0..4], &[2, 0, 0, 0]);
        assert_eq!(&dst[4..6], b"hi");
    }

    #[test]
    fn test_encode_max_frame_length_rejection() {
        let mut codec = LengthDelimitedCodec::builder()
            .max_frame_length(3)
            .new_codec();
        let mut dst = BytesMut::new();
        let data = BytesMut::from("toolong");

        let err = codec.encode(data, &mut dst).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("max_frame_length"));
    }

    #[test]
    fn test_encode_rejects_length_that_exceeds_length_field_capacity() {
        let mut codec = LengthDelimitedCodec::builder()
            .length_field_length(1)
            .length_adjustment(-32)
            .num_skip(1)
            .max_frame_length(512)
            .new_codec();
        let mut dst = BytesMut::from(&b"existing"[..]);
        let original = dst.clone();
        let payload = BytesMut::from(vec![0xAB; 240].as_slice());

        let err = codec.encode(payload, &mut dst).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string()
                .contains("encoded length exceeds length_field_length capacity")
        );
        assert_eq!(dst, original, "encode must not partially mutate dst");
    }

    fn encode_golden_frame(
        length_field_length: usize,
        big_endian: bool,
        length_adjustment: isize,
    ) -> BytesMut {
        let mut builder = LengthDelimitedCodec::builder()
            .length_field_length(length_field_length)
            .num_skip(length_field_length)
            .length_adjustment(length_adjustment);
        builder = if big_endian {
            builder.big_endian()
        } else {
            builder.little_endian()
        };

        let mut codec = builder.new_codec();
        let mut dst = BytesMut::new();
        codec
            .encode(BytesMut::from(&b"lock"[..]), &mut dst)
            .unwrap();
        dst
    }

    #[test]
    fn length_delim_goldens_match_frozen_wire_prefixes() {
        let cases = [
            (
                "u8",
                1usize,
                true,
                0isize,
                include_bytes!("../../tests/goldens/length_delim/u8.bin").as_slice(),
            ),
            (
                "u8_adjusted",
                1,
                true,
                -2,
                include_bytes!("../../tests/goldens/length_delim/u8_adjusted.bin").as_slice(),
            ),
            (
                "u16_be",
                2,
                true,
                0,
                include_bytes!("../../tests/goldens/length_delim/u16_be.bin").as_slice(),
            ),
            (
                "u16_be_adjusted",
                2,
                true,
                -2,
                include_bytes!("../../tests/goldens/length_delim/u16_be_adjusted.bin").as_slice(),
            ),
            (
                "u16_le",
                2,
                false,
                0,
                include_bytes!("../../tests/goldens/length_delim/u16_le.bin").as_slice(),
            ),
            (
                "u16_le_adjusted",
                2,
                false,
                -2,
                include_bytes!("../../tests/goldens/length_delim/u16_le_adjusted.bin").as_slice(),
            ),
            (
                "u32_be",
                4,
                true,
                0,
                include_bytes!("../../tests/goldens/length_delim/u32_be.bin").as_slice(),
            ),
            (
                "u32_be_adjusted",
                4,
                true,
                -2,
                include_bytes!("../../tests/goldens/length_delim/u32_be_adjusted.bin").as_slice(),
            ),
            (
                "u32_le",
                4,
                false,
                0,
                include_bytes!("../../tests/goldens/length_delim/u32_le.bin").as_slice(),
            ),
            (
                "u32_le_adjusted",
                4,
                false,
                -2,
                include_bytes!("../../tests/goldens/length_delim/u32_le_adjusted.bin").as_slice(),
            ),
        ];

        for (name, field_len, big_endian, adjustment, expected) in cases {
            let encoded = encode_golden_frame(field_len, big_endian, adjustment);
            assert_eq!(
                encoded.as_ref(),
                expected,
                "golden mismatch for {name}: {:?}",
                encoded
            );
        }
    }

    // ================================================================================
    // METAMORPHIC TESTING SUITE
    // ================================================================================

    /// Configuration for metamorphic testing
    #[derive(Debug, Clone)]
    struct MetamorphicTestConfig {
        /// Codec configuration
        length_field_offset: usize,
        length_field_length: usize,
        length_adjustment: isize,
        num_skip: usize,
        max_frame_length: usize,
        big_endian: bool,
    }

    impl Default for MetamorphicTestConfig {
        fn default() -> Self {
            Self {
                length_field_offset: 0,
                length_field_length: 4,
                length_adjustment: 0,
                num_skip: 4,
                max_frame_length: 8 * 1024 * 1024,
                big_endian: true,
            }
        }
    }

    impl MetamorphicTestConfig {
        fn build_codec(&self) -> LengthDelimitedCodec {
            let mut builder = LengthDelimitedCodec::builder()
                .length_field_offset(self.length_field_offset)
                .length_field_length(self.length_field_length)
                .length_adjustment(self.length_adjustment)
                .num_skip(self.num_skip)
                .max_frame_length(self.max_frame_length);

            if self.big_endian {
                builder = builder.big_endian();
            } else {
                builder = builder.little_endian();
            }

            builder.new_codec()
        }
    }

    /// Deterministic RNG extension for testing
    trait DetRngExt {
        fn gen_range(&mut self, range: std::ops::Range<usize>) -> usize;
        fn gen_range_inclusive(&mut self, range: std::ops::RangeInclusive<usize>) -> usize;
    }

    impl DetRngExt for crate::util::det_rng::DetRng {
        fn gen_range(&mut self, range: std::ops::Range<usize>) -> usize {
            if range.is_empty() {
                range.start
            } else {
                range.start + (self.next_u64() as usize % (range.end - range.start))
            }
        }

        fn gen_range_inclusive(&mut self, range: std::ops::RangeInclusive<usize>) -> usize {
            self.gen_range(*range.start()..*range.end() + 1)
        }
    }

    /// Generate deterministic test data
    fn generate_test_payload(rng: &mut crate::util::det_rng::DetRng, size: usize) -> BytesMut {
        let mut data = BytesMut::with_capacity(size);
        for _ in 0..size {
            data.put_u8((rng.next_u64() % 256) as u8);
        }
        data
    }

    /// Generate test configurations for metamorphic testing
    fn generate_test_configs(
        rng: &mut crate::util::det_rng::DetRng,
        count: usize,
    ) -> Vec<MetamorphicTestConfig> {
        (0..count)
            .map(|_| MetamorphicTestConfig {
                length_field_offset: rng.gen_range(0..3),
                length_field_length: rng.gen_range_inclusive(1..=4),
                length_adjustment: (rng.next_u64() % 21) as isize - 10,
                num_skip: rng.gen_range(0..8),
                max_frame_length: rng.gen_range_inclusive(100..=1024),
                big_endian: (rng.next_u64() % 2) == 0,
            })
            .collect()
    }

    // ================================================================================
    // MR1: Round-Trip Property (encode(decode(x)) == x)
    // ================================================================================

    #[test]
    fn metamorphic_round_trip_property() {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let mut rng = crate::util::det_rng::DetRng::new(seed);

        let configs = generate_test_configs(&mut rng, 20);

        for config in configs {
            let mut encoder = config.build_codec();
            let mut decoder = config.build_codec();

            // Test various payload sizes
            for size in [0, 1, 10, 100, 255] {
                if size <= config.max_frame_length {
                    let original_payload = generate_test_payload(&mut rng, size);

                    // Encode payload
                    let mut encoded = BytesMut::new();
                    if encoder
                        .encode(original_payload.clone(), &mut encoded)
                        .is_ok()
                    {
                        let header_len = config.length_field_offset + config.length_field_length;
                        let total_frame_len = header_len + original_payload.len();

                        match decoder.decode(&mut encoded) {
                            Ok(Some(frame)) => {
                                // The frame should contain the original payload
                                // Note: The frame might include header bytes if num_skip < header_len
                                if config.num_skip >= header_len {
                                    let skipped_payload = config.num_skip - header_len;
                                    let expected_payload = &original_payload[skipped_payload..];
                                    // Full header skipped; if num_skip extends past the header,
                                    // the returned frame is the remaining payload suffix.
                                    assert_eq!(
                                        &frame[..],
                                        expected_payload,
                                        "Round-trip failed for config {:?}, size {}",
                                        config,
                                        size
                                    );
                                } else {
                                    // Partial header retained, payload should be at the end
                                    let payload_start = header_len.saturating_sub(config.num_skip);
                                    assert_eq!(
                                        &frame[payload_start..],
                                        &original_payload[..],
                                        "Round-trip payload mismatch for config {:?}, size {}",
                                        config,
                                        size
                                    );
                                }
                            }
                            Err(err) => {
                                assert!(
                                    config.num_skip > total_frame_len,
                                    "Decode error {err:?} for decodable config {:?}, size {}",
                                    config,
                                    size
                                );
                                assert_eq!(err.kind(), io::ErrorKind::InvalidData);
                                assert!(
                                    err.to_string()
                                        .contains("num_skip exceeds total frame length"),
                                    "Unexpected decode error for config {:?}, size {}: {err:?}",
                                    config,
                                    size
                                );
                            }
                            Ok(None) => panic!(
                                // ubs:ignore - test logic
                                "Complete encoded frame did not decode for config {:?}, size {}",
                                config, size
                            ),
                        }
                    }
                }
            }
        }
    }

    // ================================================================================
    // MR2: Partial-Frame Handling Preserves State
    // ================================================================================

    #[test]
    fn metamorphic_partial_frame_state_preservation() {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let mut rng = crate::util::det_rng::DetRng::new(seed);

        let config = MetamorphicTestConfig::default();
        let payload = generate_test_payload(&mut rng, 20);

        // Encode a complete frame
        let mut encoder = config.build_codec();
        let mut encoded = BytesMut::new();
        encoder.encode(payload.clone(), &mut encoded).unwrap();

        // Split the encoded data at various points
        for split_point in 1..encoded.len() {
            let mut decoder1 = config.build_codec();
            let mut decoder2 = config.build_codec();
            let mut part1 = encoded.clone();
            let part2 = part1.split_off(split_point);

            // Decoder 1: Process partial data first, then complete
            let result1_partial = decoder1.decode(&mut part1).unwrap();
            assert!(
                result1_partial.is_none(),
                "Partial frame should return None"
            );

            part1.extend_from_slice(&part2);
            let result1_complete = decoder1.decode(&mut part1).unwrap();

            // Decoder 2: Process complete data at once
            let mut complete_data = encoded.clone();
            let result2_complete = decoder2.decode(&mut complete_data).unwrap();

            // Both decoders should produce the same result
            assert_eq!(
                result1_complete, result2_complete,
                "Partial frame handling changed result at split point {}",
                split_point
            );
        }
    }

    fn encode_length_prefix_for_test(
        length: u64,
        length_field_length: usize,
        big_endian: bool,
    ) -> Vec<u8> {
        let max_value = max_length_field_value(length_field_length).unwrap();
        assert!(
            length <= max_value,
            "test length {} exceeds {}-byte field capacity {}",
            length,
            length_field_length,
            max_value
        );

        let bytes = if big_endian {
            length.to_be_bytes()
        } else {
            length.to_le_bytes()
        };

        if big_endian {
            bytes[bytes.len() - length_field_length..].to_vec()
        } else {
            bytes[..length_field_length].to_vec()
        }
    }

    fn decode_all_available_frames(
        codec: &mut LengthDelimitedCodec,
        src: &mut BytesMut,
    ) -> io::Result<Vec<BytesMut>> {
        let mut decoded = Vec::new();
        while let Some(frame) = codec.decode(src)? {
            decoded.push(frame);
        }
        Ok(decoded)
    }

    // ================================================================================
    // MR3: Max Frame Size Rejections
    // ================================================================================

    #[test]
    fn metamorphic_max_frame_size_rejections() {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let mut rng = crate::util::det_rng::DetRng::new(seed);

        // Test with various max frame length limits
        for max_len in [10, 50, 100, 500] {
            let config = MetamorphicTestConfig {
                max_frame_length: max_len,
                ..Default::default()
            };

            let mut encoder = config.build_codec();
            let mut decoder = config.build_codec();

            // Test payloads around the limit
            for size in [max_len - 1, max_len, max_len + 1, max_len * 2] {
                let payload = generate_test_payload(&mut rng, size);
                let mut encoded = BytesMut::new();

                // Encode should reject oversized frames
                let encode_result = encoder.encode(payload, &mut encoded);

                if size > max_len {
                    assert!(
                        encode_result.is_err(),
                        "Encoder should reject frame size {} > max_len {}",
                        size,
                        max_len
                    );
                    assert_eq!(
                        encode_result.unwrap_err().kind(),
                        io::ErrorKind::InvalidData
                    );
                } else {
                    assert!(
                        encode_result.is_ok(),
                        "Encoder should accept frame size {} <= max_len {}",
                        size,
                        max_len
                    );

                    // If encoding succeeded, decoding should too
                    let decode_result = decoder.decode(&mut encoded);
                    assert!(
                        decode_result.is_ok(),
                        "Decoder should accept frame that encoder produced"
                    );
                }
            }

            // Test direct decoder rejection of oversized frames
            let mut decoder_direct = config.build_codec();
            let mut crafted_frame = BytesMut::new();

            // Craft a frame that claims to be oversized
            let oversized_len = max_len + 100;
            crafted_frame.put_u32(oversized_len as u32);
            let decode_result = decoder_direct.decode(&mut crafted_frame);

            // Decoder should reject this during header parsing
            assert!(
                decode_result.is_err(),
                "Decoder should reject oversized frame length in header"
            );
        }
    }

    #[test]
    fn metamorphic_decoder_boundary_fragmentation_preserves_multi_frame_arrival_order() {
        let configs = [
            MetamorphicTestConfig {
                length_field_length: 1,
                num_skip: 1,
                max_frame_length: 31,
                big_endian: true,
                ..Default::default()
            },
            MetamorphicTestConfig {
                length_field_length: 1,
                num_skip: 1,
                max_frame_length: 31,
                big_endian: false,
                ..Default::default()
            },
            MetamorphicTestConfig {
                length_field_length: 2,
                num_skip: 2,
                max_frame_length: 257,
                big_endian: true,
                ..Default::default()
            },
            MetamorphicTestConfig {
                length_field_length: 4,
                num_skip: 4,
                max_frame_length: 257,
                big_endian: false,
                ..Default::default()
            },
        ];

        for config in configs {
            let sizes = [
                0,
                1,
                config.max_frame_length.saturating_sub(1),
                config.max_frame_length,
            ];
            let payloads: Vec<BytesMut> = sizes
                .into_iter()
                .enumerate()
                .map(|(index, size)| {
                    let fill = b'A'.saturating_add(index as u8);
                    let mut payload = BytesMut::with_capacity(size);
                    payload.resize(size, fill);
                    payload
                })
                .collect();

            let mut encoder = config.build_codec();
            let mut encoded_stream = BytesMut::new();
            for payload in &payloads {
                encoder
                    .encode(payload.clone(), &mut encoded_stream)
                    .expect("boundary payload must encode");
            }

            let mut reference_decoder = config.build_codec();
            let mut reference_stream = encoded_stream.clone();
            let expected =
                decode_all_available_frames(&mut reference_decoder, &mut reference_stream).unwrap();
            assert!(
                reference_stream.is_empty(),
                "reference decode should drain the full stream for {config:?}"
            );
            assert_eq!(
                expected, payloads,
                "reference decode should preserve boundary payload order for {config:?}"
            );

            let mut incremental_decoder = config.build_codec();
            let mut fragmented_stream = BytesMut::new();
            let mut fragmented_source = encoded_stream.clone();
            let mut actual = Vec::new();

            while !fragmented_source.is_empty() {
                let next_byte = fragmented_source.split_to(1);
                fragmented_stream.extend_from_slice(&next_byte);
                actual.extend(
                    decode_all_available_frames(&mut incremental_decoder, &mut fragmented_stream)
                        .unwrap(),
                );
            }

            assert_eq!(
                actual, expected,
                "byte-wise fragmentation changed arrival order for {config:?}"
            );
            assert!(
                fragmented_stream.is_empty(),
                "fragmented decoder should drain all buffered bytes for {config:?}"
            );
        }
    }

    #[test]
    fn metamorphic_decoder_boundary_oversized_prefixes_reject_without_consuming_header() {
        for (length_field_length, big_endian, max_frame_length) in [
            (1, true, 31usize),
            (1, false, 31usize),
            (2, true, 257usize),
            (2, false, 257usize),
            (4, true, 257usize),
            (8, false, 257usize),
        ] {
            let config = MetamorphicTestConfig {
                length_field_length,
                num_skip: length_field_length,
                max_frame_length,
                big_endian,
                ..Default::default()
            };

            let mut exact_boundary_decoder = config.build_codec();
            let exact_header = encode_length_prefix_for_test(
                max_frame_length as u64,
                length_field_length,
                big_endian,
            );
            let mut exact_boundary = BytesMut::from(exact_header.as_slice());
            assert!(
                exact_boundary_decoder
                    .decode(&mut exact_boundary)
                    .expect("exact-max header should not error without payload")
                    .is_none(),
                "exact-max frame should wait for payload bytes for {:?}",
                config
            );
            assert_eq!(
                exact_boundary.as_ref(),
                &[] as &[u8],
                "exact-max header should be consumed once the decoder enters payload-wait state for {:?}",
                config
            );

            let exact_payload = vec![0xAB; max_frame_length];
            exact_boundary.extend_from_slice(&exact_payload);
            let decoded = exact_boundary_decoder
                .decode(&mut exact_boundary)
                .expect("exact-max payload should decode")
                .expect("exact-max payload should be emitted");
            assert_eq!(
                decoded.as_ref(),
                exact_payload.as_slice(),
                "exact-max payload bytes changed for {:?}",
                config
            );
            assert!(
                exact_boundary.is_empty(),
                "exact-max decode should drain the buffer for {:?}",
                config
            );

            let max_value = max_length_field_value(length_field_length).unwrap();
            let mut oversized_lengths = Vec::new();
            for candidate in [
                max_frame_length as u64 + 1,
                max_frame_length as u64 + 17,
                max_frame_length as u64 * 2 + 1,
                max_value,
            ] {
                if candidate > max_frame_length as u64
                    && candidate <= max_value
                    && !oversized_lengths.contains(&candidate)
                {
                    oversized_lengths.push(candidate);
                }
            }

            for oversized_length in oversized_lengths {
                let header = encode_length_prefix_for_test(
                    oversized_length,
                    length_field_length,
                    big_endian,
                );
                let mut decoder = config.build_codec();
                let mut src = BytesMut::from(header.as_slice());
                let error = decoder
                    .decode(&mut src)
                    .expect_err("oversized prefix must be rejected");
                assert_eq!(
                    error.kind(),
                    io::ErrorKind::InvalidData,
                    "oversized prefix must raise InvalidData for {:?}",
                    config
                );
                assert_eq!(
                    src.as_ref(),
                    header.as_slice(),
                    "oversized-prefix rejection must not consume header bytes for {:?}",
                    config
                );
            }
        }
    }

    // ================================================================================
    // MR4: Length-Prefix Byte-Order Consistency
    // ================================================================================

    #[test]
    fn metamorphic_byte_order_consistency() {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let mut rng = crate::util::det_rng::DetRng::new(seed);

        let payload = generate_test_payload(&mut rng, 100);

        // Test different byte orders with the same logical configuration
        let base_config = MetamorphicTestConfig {
            length_field_length: 4,
            ..Default::default()
        };

        let big_endian_config = MetamorphicTestConfig {
            big_endian: true,
            ..base_config
        };

        let little_endian_config = MetamorphicTestConfig {
            big_endian: false,
            ..base_config
        };

        // Encode with both byte orders
        let mut be_encoder = big_endian_config.build_codec();
        let mut le_encoder = little_endian_config.build_codec();

        let mut be_encoded = BytesMut::new();
        let mut le_encoded = BytesMut::new();

        be_encoder.encode(payload.clone(), &mut be_encoded).unwrap();
        le_encoder.encode(payload.clone(), &mut le_encoded).unwrap();

        // Wire formats should be different for multi-byte lengths
        if payload.len() > 255 {
            assert_ne!(
                be_encoded, le_encoded,
                "Big-endian and little-endian should produce different wire formats"
            );

            // But the length fields should be byte-swapped versions of each other
            let be_len =
                u32::from_be_bytes([be_encoded[0], be_encoded[1], be_encoded[2], be_encoded[3]]);
            let le_len =
                u32::from_le_bytes([le_encoded[0], le_encoded[1], le_encoded[2], le_encoded[3]]);
            assert_eq!(
                be_len, le_len,
                "Length values should be equal when interpreted correctly"
            );
        }

        // Decoders should extract the same payload regardless of byte order
        let mut be_decoder = big_endian_config.build_codec();
        let mut le_decoder = little_endian_config.build_codec();

        let be_decoded = be_decoder.decode(&mut be_encoded).unwrap().unwrap();
        let le_decoded = le_decoder.decode(&mut le_encoded).unwrap().unwrap();

        // Extract just the payload from both results
        let header_len = base_config.length_field_offset + base_config.length_field_length;
        let payload_start = if base_config.num_skip >= header_len {
            0
        } else {
            header_len.saturating_sub(base_config.num_skip)
        };

        assert_eq!(
            &be_decoded[payload_start..],
            &le_decoded[payload_start..],
            "Decoded payloads should be identical regardless of byte order"
        );
    }

    // ================================================================================
    // MR5: LabRuntime Replay Identical
    // ================================================================================

    #[test]
    fn metamorphic_lab_runtime_replay_identical() {
        // Test deterministic behavior with fixed seed
        const SEED: u64 = 0x1234_5678_9ABC_DEF0;

        // Run the same test sequence multiple times with the same seed
        let results: Vec<Vec<BytesMut>> = (0..3)
            .map(|_| {
                let mut rng = crate::util::det_rng::DetRng::new(SEED);
                let mut frames = Vec::new();

                // Generate and process test frames deterministically
                for _ in 0..10 {
                    let config = MetamorphicTestConfig {
                        length_field_length: 2,
                        num_skip: 2,
                        max_frame_length: 1000,
                        big_endian: (rng.next_u64() % 2) == 0,
                        ..Default::default()
                    };

                    let payload_size = rng.gen_range(1..100);
                    let payload = generate_test_payload(&mut rng, payload_size);

                    let mut encoder = config.build_codec();
                    let mut decoder = config.build_codec();

                    let mut encoded = BytesMut::new();
                    if encoder.encode(payload, &mut encoded).is_ok() {
                        if let Ok(Some(frame)) = decoder.decode(&mut encoded) {
                            frames.push(frame);
                        }
                    }
                }

                frames
            })
            .collect();

        // All runs should produce identical results
        for i in 1..results.len() {
            assert_eq!(
                results[0], results[i],
                "Run {} produced different results than run 0 - non-deterministic behavior detected",
                i
            );
        }

        // Results should be non-empty (basic sanity check)
        assert!(
            !results[0].is_empty(),
            "Should have processed some frames successfully"
        );
    }

    // ================================================================================
    // Composite Metamorphic Relations
    // ================================================================================

    #[test]
    fn metamorphic_composite_round_trip_with_partial_frames() {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let mut rng = crate::util::det_rng::DetRng::new(seed);

        let config = MetamorphicTestConfig::default();
        let payload = generate_test_payload(&mut rng, 50);

        // Encode
        let mut encoder = config.build_codec();
        let mut encoded = BytesMut::new();
        encoder.encode(payload.clone(), &mut encoded).unwrap();

        // Decode with random partial reads
        let mut decoder = config.build_codec();
        let mut remaining = encoded.clone();
        let mut accumulated = BytesMut::new();

        while !remaining.is_empty() {
            let chunk_size = rng.gen_range(1..remaining.len() + 1).min(remaining.len());
            let chunk = remaining.split_to(chunk_size);
            accumulated.put_slice(&chunk);

            if let Ok(Some(frame)) = decoder.decode(&mut accumulated) {
                // Extract payload from frame
                let header_len = config.length_field_offset + config.length_field_length;
                let payload_start = if config.num_skip >= header_len {
                    0
                } else {
                    header_len.saturating_sub(config.num_skip)
                };

                assert_eq!(
                    &frame[payload_start..],
                    &payload[..],
                    "Composite round-trip with partial frames failed"
                );
                break;
            }
        }
    }

    #[test]
    fn metamorphic_cross_configuration_compatibility() {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let mut rng = crate::util::det_rng::DetRng::new(seed);

        // Test that different configurations that should be compatible actually are
        let base_config = MetamorphicTestConfig {
            length_field_length: 4,
            num_skip: 4,
            max_frame_length: 1000,
            ..Default::default()
        };

        // Variations that should be compatible
        let configs = vec![
            base_config.clone(),
            MetamorphicTestConfig {
                big_endian: false,
                ..base_config.clone()
            },
            MetamorphicTestConfig {
                length_field_offset: 2,
                num_skip: 6,
                ..base_config.clone()
            },
        ];

        let payload = generate_test_payload(&mut rng, 30);

        // Each config should be able to round-trip the data
        for config in &configs {
            let mut encoder = config.build_codec();
            let mut decoder = config.build_codec();

            let mut encoded = BytesMut::new();
            encoder.encode(payload.clone(), &mut encoded).unwrap();

            let decoded = decoder.decode(&mut encoded).unwrap().unwrap();

            // Verify the payload is preserved
            let header_len = config.length_field_offset + config.length_field_length;
            let payload_start = if config.num_skip >= header_len {
                0
            } else {
                header_len.saturating_sub(config.num_skip)
            };

            assert_eq!(
                &decoded[payload_start..],
                &payload[..],
                "Configuration {:?} failed round-trip test",
                config
            );
        }
    }

    /// MR7: Encoded-Length Monotonicity (br-asupersync-acz1zk)
    ///
    /// Property: for a fixed LengthDelimitedCodec configuration,
    ///     payload_a.len() <= payload_b.len()
    ///   ⇒
    ///     encoded(payload_a).len() <= encoded(payload_b).len()
    ///
    /// This is the canonical sanity check for any framing codec —
    /// violations indicate either non-deterministic header sizing
    /// (length_field_length should be const per codec instance) or a
    /// bug where the adjustment field accidentally inverts the encoded
    /// ordering.
    ///
    /// The property holds trivially for the current implementation
    /// (header is fixed-width, body is appended verbatim) but the lack
    /// of an explicit test means any future variable-length-header
    /// refactor or compression integration could regress without
    /// detection. This regression guard locks in the invariant.
    ///
    /// Catches: variable-header reframings, header-compression
    /// experiments, length_adjustment that accidentally inverts
    /// ordering, padding policies that grow shorter inputs more than
    /// longer ones.
    #[test]
    fn mr_encoded_length_monotonicity() {
        // Sweep across multiple length-field widths and a representative
        // payload-length grid. The grid is dense in the small-payload
        // region (where header overhead dominates), and skips to a few
        // large jumps to catch any width-dependent bug.
        for length_field_length in [1usize, 2, 4, 8] {
            // 1-byte width caps payloads at 255; respect that cap.
            let cap = match length_field_length {
                1 => 255,
                2 => 65_535,
                _ => 100_000,
            };
            let lengths: Vec<usize> = vec![0, 1, 2, 7, 16, 31, 64, 100, 127, 200, 255]
                .into_iter()
                .filter(|&l| l <= cap)
                .chain(if cap > 1024 {
                    vec![1024, 4096, 65_535]
                } else {
                    vec![]
                })
                .filter(|&l| l <= cap)
                .collect();

            // Encode each length and capture the encoded-output size.
            let mut encoded_sizes: Vec<(usize, usize)> = Vec::new();
            for &payload_len in &lengths {
                let mut codec = LengthDelimitedCodec::builder()
                    .length_field_length(length_field_length)
                    .max_frame_length(8 * 1024 * 1024)
                    .new_codec();
                let payload = vec![0xA5u8; payload_len];
                let mut buf = BytesMut::new();
                codec
                    .encode(BytesMut::from(&payload[..]), &mut buf)
                    .unwrap_or_else(|e| {
                        panic!(
                            "encode failed for width={length_field_length} len={payload_len}: {e}"
                        )
                    });
                encoded_sizes.push((payload_len, buf.len()));
            }

            // Property: for every (a, b) pair with a.payload_len <=
            // b.payload_len, a.encoded_len MUST be <= b.encoded_len.
            for i in 0..encoded_sizes.len() {
                for j in (i + 1)..encoded_sizes.len() {
                    let (a_len, a_enc) = encoded_sizes[i];
                    let (b_len, b_enc) = encoded_sizes[j];
                    assert!(
                        a_len <= b_len,
                        "test bug: lengths not sorted ({a_len} > {b_len})"
                    );
                    assert!(
                        a_enc <= b_enc,
                        "MONOTONICITY VIOLATION (width={length_field_length}): \
                         payload {a_len}B → encoded {a_enc}B, \
                         payload {b_len}B → encoded {b_enc}B; \
                         smaller input produced LARGER encoded output"
                    );
                }
            }

            // Additional invariant: encoded length = header + payload.
            // (Locks the current fixed-header semantics — if a future
            // refactor introduces variable headers, this assertion
            // forces a deliberate update.)
            for &(payload_len, encoded_len) in &encoded_sizes {
                assert_eq!(
                    encoded_len,
                    payload_len + length_field_length,
                    "encoded == payload + header invariant violated for \
                     width={length_field_length} payload_len={payload_len}"
                );
            }
        }
    }

    /// MR8: Exhaustive Split-Input Invariance (br-asupersync-426vdh)
    ///
    /// Property: encode N items into a single buffer B; for EVERY split
    /// position k in 1..B.len(), feeding (B[..k], B[k..]) sequentially
    /// through the decoder MUST yield all N items in order, byte-equal
    /// to the originals.
    ///
    /// Catches:
    ///   * decoder state-machine bugs where a partial-frame parse
    ///     mutates state non-recoverably
    ///   * length-prefix bugs where the decoder consumes header bytes
    ///     prematurely
    ///   * buffer-management issues where a sub-buffer carryover loses
    ///     bytes between calls
    ///
    /// This is a Decoder-level property; the Framed wrapper (src/codec/
    /// framed.rs) uses LengthDelimitedCodec via the same Decoder trait,
    /// so this test covers the `framed` code path indirectly. The
    /// existing `metamorphic_decoder_boundary_fragmentation_*` test
    /// covers SOME splits but not exhaustively across all positions.
    /// TCP delivers data in arbitrary chunk sizes — every frame
    /// boundary IS a split point in production.
    #[test]
    fn mr_exhaustive_split_input_invariance() {
        // Build encoded bytes for N=4 frames of varying sizes.
        let frames: Vec<Vec<u8>> = vec![
            b"first".to_vec(),
            vec![0xAB; 100],
            b"third frame with spaces".to_vec(),
            vec![0u8; 256],
        ];
        let mut encoder = LengthDelimitedCodec::new();
        let mut full = BytesMut::new();
        for frame in &frames {
            encoder
                .encode(BytesMut::from(&frame[..]), &mut full)
                .expect("encode");
        }
        let total_len = full.len();
        let serialized: Vec<u8> = full.to_vec();

        // For every split position 1..total_len, feed two halves and
        // assert all N frames decode in order.
        for split_at in 1..total_len {
            let left = &serialized[..split_at];
            let right = &serialized[split_at..];
            let mut decoder = LengthDelimitedCodec::new();
            let mut buf = BytesMut::from(left);
            let mut emitted: Vec<Vec<u8>> = Vec::new();

            // Drain decode after first feed.
            while let Some(frame) = decoder.decode(&mut buf).expect("decode left") {
                emitted.push(frame.to_vec());
            }
            // Append right half + drain again.
            buf.extend_from_slice(right);
            while let Some(frame) = decoder.decode(&mut buf).expect("decode right") {
                emitted.push(frame.to_vec());
            }

            assert_eq!(
                emitted.len(),
                frames.len(),
                "split_at={split_at}: emitted {} frames, expected {}",
                emitted.len(),
                frames.len()
            );
            for (i, (got, expected)) in emitted.iter().zip(frames.iter()).enumerate() {
                assert_eq!(got, expected, "split_at={split_at}: frame {i} mismatch");
            }
            assert!(
                buf.is_empty(),
                "split_at={split_at}: leftover {} bytes after drain",
                buf.len()
            );
        }
    }

    /// br-asupersync-ooqkxe — encode() must surface `InvalidData` (not
    /// panic, not wrap, not silently under-reserve) when
    /// `length_field_offset + length_field_length` overflows usize.
    #[test]
    fn encode_rejects_header_len_overflow() {
        let mut codec = LengthDelimitedCodec::builder()
            .length_field_offset(usize::MAX)
            .length_field_length(4)
            .max_frame_length(usize::MAX)
            .new_codec();
        let mut dst = BytesMut::new();
        let mut item = BytesMut::new();
        item.put_slice(b"hello");
        let err = codec
            .encode(item, &mut dst)
            .expect_err("must reject header_len overflow");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("header length"),
            "unexpected error message: {}",
            err
        );
    }

    /// br-asupersync-ooqkxe — encode() must surface `InvalidData` when the
    /// total reserve budget (header + frame) overflows usize, even if
    /// header_len itself is fine. We engineer this by giving header_len a
    /// near-MAX offset and a frame near-MAX length (the real-world attack
    /// surface is an attacker-controlled offset combined with a large but
    /// allowed frame).
    #[test]
    fn encode_rejects_total_reserve_overflow() {
        // Pick offset so header_len is just under usize::MAX. Then frame
        // length doesn't have to be MAX itself — just enough to overflow
        // the sum.
        let offset = usize::MAX - 16;
        let mut codec = LengthDelimitedCodec::builder()
            .length_field_offset(offset)
            .length_field_length(4)
            .max_frame_length(usize::MAX)
            .new_codec();
        let mut dst = BytesMut::new();
        // A 1024-byte frame plus an offset within 16 of usize::MAX
        // overflows; header_len = offset + 4 = MAX-12; total = MAX-12+1024
        // wraps. Construct the frame and assert overflow detection.
        let mut item = BytesMut::with_capacity(1024);
        for _ in 0..1024 {
            item.put_u8(0);
        }
        let err = codec
            .encode(item, &mut dst)
            .expect_err("must reject total reservation overflow");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// br-asupersync-ooqkxe — happy-path: zero-length frame with valid
    /// offset/length must encode successfully (regression guard against
    /// over-eager rejection).
    #[test]
    fn encode_zero_length_frame_succeeds() {
        let mut codec = LengthDelimitedCodec::new();
        let mut dst = BytesMut::new();
        let item = BytesMut::new();
        codec.encode(item, &mut dst).expect("zero-length frame OK");
        // Default codec writes a 4-byte big-endian length of zero.
        assert_eq!(&dst[..], &[0, 0, 0, 0]);
    }

    /// br-asupersync-ooqkxe — happy-path: max-frame-length frame at the
    /// boundary must encode successfully when offset+length doesn't
    /// overflow.
    #[test]
    fn encode_at_max_frame_length_succeeds() {
        let max = 1024;
        let mut codec = LengthDelimitedCodec::builder()
            .length_field_length(4)
            .max_frame_length(max)
            .new_codec();
        let mut dst = BytesMut::new();
        let mut item = BytesMut::with_capacity(max);
        for _ in 0..max {
            item.put_u8(0xAB);
        }
        codec.encode(item, &mut dst).expect("max frame OK");
        // 4-byte length prefix + max-byte payload.
        assert_eq!(dst.len(), 4 + max);
    }
}
