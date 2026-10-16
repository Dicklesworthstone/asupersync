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
    num_skip: Option<usize>,
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
        1..=7 => Ok((1u64 << length_field_length.saturating_mul(8)).saturating_sub(1)),
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
            num_skip: None,
            max_frame_length: 8_usize.saturating_mul(1024).saturating_mul(1024),
            big_endian: true,
        }
    }
}

impl Default for LengthDelimitedCodec {
    fn default() -> Self {
        Self::new()
    }
}

macro_rules! builder_setters {
    ($(
        $(#[$meta:meta])*
        $name:ident: $ty:ty;
    )*) => {
        $(
            $(#[$meta])*
            #[inline]
            #[must_use]
            pub fn $name(mut self, val: $ty) -> Self {
                self.$name = val;
                self
            }
        )*
    };
}

impl LengthDelimitedCodecBuilder {
    builder_setters! {
        /// Sets the length field offset for decoding.
        length_field_offset: usize;

        /// Sets the length field length (1..=8 bytes).
        length_field_length: usize;

        /// Adjusts the reported length by this amount.
        length_adjustment: isize;

        /// Sets the maximum frame length.
        max_frame_length: usize;
    }

    /// Number of bytes to skip before frame data when decoding.
    ///
    /// When unset, matches `tokio-util` by defaulting to
    /// `length_field_offset + length_field_length`.
    #[inline]
    #[must_use]
    pub fn num_skip(mut self, val: usize) -> Self {
        self.num_skip = Some(val);
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
                value |= u64::from(b) << shift.saturating_mul(8);
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

    fn num_skip(&self, header_len: usize) -> usize {
        self.builder.num_skip.unwrap_or(header_len)
    }

    /// Bytes remaining on the wire after the length field has been consumed.
    ///
    /// `num_skip` may extend past the length field through an application header;
    /// recovery must drain that suffix before the adjusted frame body. Unknown or
    /// unrepresentable geometry fails closed by keeping the decoder in Skip.
    fn recovery_wire_suffix_len(&self, header_len: usize, adjusted_frame_len: Option<u64>) -> u64 {
        let Some(adjusted_frame_len) = adjusted_frame_len else {
            return u64::MAX;
        };
        let extra_prefix_len = self.num_skip(header_len).saturating_sub(header_len);
        let Ok(extra_prefix_len) = u64::try_from(extra_prefix_len) else {
            return u64::MAX;
        };
        extra_prefix_len.saturating_add(adjusted_frame_len)
    }
}

impl Decoder for LengthDelimitedCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<BytesMut>> {
        loop {
            match self.state {
                DecodeState::Head => {
                    // br-asupersync-qj99nz: symmetry with the encode path.
                    // Previously this used `saturating_add`, which on a 32-bit
                    // target with adversarial builder configuration could
                    // saturate `header_len` to `usize::MAX` — the subsequent
                    // `total_frame_len = header_len.checked_add(frame_len)`
                    // would then wrap or pass `max_frame_length` checks while
                    // leaving the state machine in `Data(usize::MAX)`. The
                    // encode path at line ~397 already uses `checked_add` and
                    // surfaces InvalidData on overflow; the decode path now
                    // uses the same shape for the same reason.
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

                    if src.len() < header_len {
                        return Ok(None);
                    }

                    let raw_len = self.decode_head(src)?;
                    let num_skip = self.num_skip(header_len);
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
                            //
                            // The skip-count must include any application-header
                            // suffix between the length field and `num_skip`, plus
                            // the ADJUSTED body length (`raw_len +
                            // length_adjustment`). Using only the RAW
                            // (pre-adjustment) body length here desynchronizes the
                            // stream whenever `length_adjustment != 0`: it
                            // under-drains for a positive adjustment (leaving
                            // body bytes that are then mis-parsed as the next
                            // frame's header) and over-drains into the next
                            // frame's header for a negative one. Fall back to
                            // draining everything (u64::MAX) only when the
                            // adjusted length is genuinely ill-defined
                            // (length/adjustment overflow, or negative).
                            let adjusted_frame_len = i64::try_from(self.builder.length_adjustment)
                                .ok()
                                .and_then(|adj| {
                                    i64::try_from(raw_len).ok().and_then(|l| l.checked_add(adj))
                                })
                                .filter(|&adjusted| adjusted >= 0)
                                .and_then(|adjusted| u64::try_from(adjusted).ok());
                            let wire_suffix_skip =
                                self.recovery_wire_suffix_len(header_len, adjusted_frame_len);
                            let _ = src.split_to(header_len);
                            self.state = DecodeState::Skip(wire_suffix_skip);
                            return Err(e);
                        }
                    };
                    // Both length-validation failures below must recover the
                    // framing exactly like the `adjusted_frame_len` branch
                    // above (br-asupersync-o7e5xu): consume the header and
                    // enter Skip to drain this frame's wire suffix. Returning `Err`
                    // with `src` untouched leaves `state == Head`, so a direct
                    // decode-loop caller re-reads the same header and re-emits
                    // the identical error forever — a livelock. The wire prefix
                    // extends through `num_skip` when callers place application
                    // header bytes after the length field.
                    let wire_prefix_len = header_len.max(num_skip);
                    let adjusted_frame_len = u64::try_from(frame_len).ok();
                    let total_frame_len = match wire_prefix_len.checked_add(frame_len) {
                        Some(n) => n,
                        None => {
                            let _ = src.split_to(header_len);
                            self.state = DecodeState::Skip(
                                self.recovery_wire_suffix_len(header_len, adjusted_frame_len),
                            );
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "frame length overflow",
                            ));
                        }
                    };
                    let retained_len = match total_frame_len.checked_sub(num_skip) {
                        Some(n) => n,
                        None => {
                            let _ = src.split_to(header_len);
                            self.state = DecodeState::Skip(
                                self.recovery_wire_suffix_len(header_len, adjusted_frame_len),
                            );
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "num_skip exceeds total frame length",
                            ));
                        }
                    };

                    if src.len() < total_frame_len {
                        return Ok(None);
                    }

                    if num_skip > 0 {
                        let _ = src.split_to(num_skip);
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

        // br-asupersync-ooqkxe: validate header length overflow before proceeding
        // This matches the overflow check in the decoder (lines 249-258)
        if self.builder.length_field_offset == usize::MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "header length overflow: length_field_offset at maximum value",
            ));
        }
        let header_len = self
            .builder
            .length_field_offset
            .checked_add(self.builder.length_field_length)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "header length overflow"))?;

        // br-asupersync-ooqkxe: validate total reservation overflow (header + frame)
        let _total_reservation = header_len.checked_add(frame_len).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "total reservation overflow")
        })?;

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

        // br-asupersync-ooqkxe: validate total reservation overflow
        // The total reservation must account for the full header length + frame
        // even though we only emit length_field_length bytes on the wire
        let _total_len = header_len.checked_add(frame_len).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "frame buffer reservation overflows usize",
            )
        })?;

        // br-asupersync-zqnmjc — Tokio wire-compat:
        // `length_field_offset` and `num_skip` are decode-only knobs and
        // MUST NOT change the bytes emitted by the encoder. The wire prefix
        // is therefore just the encoded length field itself.
        let wire_len = self
            .builder
            .length_field_length
            .checked_add(frame_len)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "wire buffer reservation overflows usize",
                )
            })?;

        // Reserve space for the wire frame (length field + payload)
        dst.reserve(wire_len);

        // Write the length field in the configured byte order
        if self.builder.big_endian {
            match self.builder.length_field_length {
                1 => dst.put_u8(length_to_encode as u8),
                2 => dst.put_u16(length_to_encode as u16),
                3 => {
                    dst.put_u8((length_to_encode >> 16) as u8);
                    dst.put_slice(&(length_to_encode as u16).to_be_bytes());
                }
                4 => dst.put_slice(&(length_to_encode as u32).to_be_bytes()),
                5 => {
                    dst.put_u8((length_to_encode >> 32) as u8);
                    dst.put_slice(&(length_to_encode as u32).to_be_bytes());
                }
                6 => {
                    dst.put_slice(&((length_to_encode >> 32) as u16).to_be_bytes());
                    dst.put_slice(&(length_to_encode as u32).to_be_bytes());
                }
                7 => {
                    dst.put_u8((length_to_encode >> 48) as u8);
                    dst.put_slice(&((length_to_encode >> 32) as u16).to_be_bytes());
                    dst.put_slice(&(length_to_encode as u32).to_be_bytes());
                }
                8 => dst.put_slice(&length_to_encode.to_be_bytes()),
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
#[path = "length_delimited_inline_tests.rs"]
mod tests;
