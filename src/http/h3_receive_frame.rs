//! Bounded incremental frame bookkeeping for the native H3 receive adapter.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FrameHeaderError {
    AddressOverflow,
    LengthOverflow,
    PayloadTooLarge {
        payload_size: usize,
        max_size: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FrameHeader {
    pub(super) kind: u64,
    pub(super) payload_len: usize,
    pub(super) header_len: usize,
    pub(super) wire_len: usize,
}

impl FrameHeader {
    /// Decode only the two bounded QUIC varints. The payload need not exist.
    pub(super) fn decode(
        bytes: &[u8],
        max_payload_size: usize,
    ) -> Result<Option<Self>, FrameHeaderError> {
        let Some((kind, type_len)) = decode_varint(bytes) else {
            return Ok(None);
        };
        let Some((payload_len, length_len)) = decode_varint(&bytes[type_len..]) else {
            return Ok(None);
        };
        let payload_len =
            usize::try_from(payload_len).map_err(|_| FrameHeaderError::AddressOverflow)?;
        if payload_len > max_payload_size {
            return Err(FrameHeaderError::PayloadTooLarge {
                payload_size: payload_len,
                max_size: max_payload_size,
            });
        }
        let header_len = type_len + length_len;
        let wire_len = header_len
            .checked_add(payload_len)
            .ok_or(FrameHeaderError::LengthOverflow)?;
        Ok(Some(Self {
            kind,
            payload_len,
            header_len,
            wire_len,
        }))
    }
}

/// HTTP/3 frame type/length integers use QUIC's 1/2/4/8-byte encoding.
fn decode_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    let len = 1_usize << (first >> 6);
    if bytes.len() < len {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..len] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, len))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DataFrameCursor {
    remaining: usize,
}

impl DataFrameCursor {
    pub(super) const fn new(payload_len: usize) -> Self {
        Self {
            remaining: payload_len,
        }
    }

    /// Consume at most one caller-sized piece, never the following frame.
    pub(super) fn take_len(&mut self, available: usize, max_chunk_bytes: usize) -> usize {
        let len = self.remaining.min(available).min(max_chunk_bytes);
        self.remaining -= len;
        len
    }

    pub(super) const fn is_complete(self) -> bool {
        self.remaining == 0
    }
}

#[cfg(test)]
#[path = "h3_receive_frame_inline_tests.rs"]
mod tests;
