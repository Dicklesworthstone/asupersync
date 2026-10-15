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
mod tests {
    use super::*;

    fn encoded(value: u64, width: usize) -> Vec<u8> {
        let mut wire = value.to_be_bytes()[8 - width..].to_vec();
        wire[0] |= match width {
            1 => 0,
            2 => 0x40,
            4 => 0x80,
            8 => 0xc0,
            _ => panic!("unsupported QUIC varint width"),
        };
        wire
    }

    #[test]
    fn split_headers_wait_for_both_complete_varints() {
        for type_width in [1, 2, 4, 8] {
            for length_width in [1, 2, 4, 8] {
                let mut wire = encoded(0, type_width);
                wire.extend(encoded(63, length_width));
                for split in 0..wire.len() {
                    assert_eq!(FrameHeader::decode(&wire[..split], 63), Ok(None));
                }
                assert_eq!(
                    FrameHeader::decode(&wire, 63),
                    Ok(Some(FrameHeader {
                        kind: 0,
                        payload_len: 63,
                        header_len: type_width + length_width,
                        wire_len: type_width + length_width + 63,
                    }))
                );
            }
        }
    }

    #[test]
    fn declared_oversize_is_rejected_before_payload_arrives() {
        for width in [2, 4, 8] {
            let mut wire = encoded(0, 1);
            wire.extend(encoded(64, width));
            assert_eq!(
                FrameHeader::decode(&wire, 63),
                Err(FrameHeaderError::PayloadTooLarge {
                    payload_size: 64,
                    max_size: 63,
                })
            );
        }
    }

    #[test]
    fn type_and_length_boundaries_preserve_the_following_payload() {
        for value in [0, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824] {
            let width = match value {
                0..=63 => 1,
                64..=16_383 => 2,
                16_384..=1_073_741_823 => 4,
                _ => 8,
            };
            let mut wire = encoded(value, width);
            wire.extend(encoded(0, 1));
            wire.extend([0xff; 17]);
            let head = FrameHeader::decode(&wire, 0).unwrap().unwrap();
            assert_eq!(head.kind, value);
            assert_eq!(head.payload_len, 0);
            assert_eq!(head.header_len, width + 1);
            assert_eq!(head.wire_len, width + 1);
        }
    }

    #[test]
    fn maximum_varint_does_not_truncate_to_an_addressable_length() {
        let mut wire = encoded(0, 1);
        wire.extend(encoded((1_u64 << 62) - 1, 8));
        if usize::BITS < 64 {
            assert_eq!(
                FrameHeader::decode(&wire, usize::MAX),
                Err(FrameHeaderError::AddressOverflow)
            );
        } else {
            let head = FrameHeader::decode(&wire, usize::MAX).unwrap().unwrap();
            assert_eq!(head.payload_len as u64, (1_u64 << 62) - 1);
            assert_eq!(head.header_len, 9);
        }
    }

    #[test]
    fn data_cursor_is_bounded_and_never_consumes_a_following_frame() {
        let mut cursor = DataFrameCursor::new(11);
        assert_eq!(cursor.take_len(100, 4), 4);
        assert!(!cursor.is_complete());
        assert_eq!(cursor.take_len(2, 4), 2);
        assert_eq!(cursor.take_len(0, 4), 0);
        assert!(!cursor.is_complete(), "empty input cannot become FIN");
        assert_eq!(cursor.take_len(100, 4), 4);
        assert_eq!(cursor.take_len(100, 4), 1);
        assert!(cursor.is_complete());
        assert_eq!(cursor.take_len(100, 4), 0);
    }

    #[test]
    fn empty_data_frame_is_complete_and_zero_budget_does_not_consume() {
        assert!(DataFrameCursor::new(0).is_complete());
        let mut cursor = DataFrameCursor::new(1);
        assert_eq!(cursor.take_len(1, 0), 0);
        assert!(!cursor.is_complete());
        assert_eq!(cursor.take_len(1, 1), 1);
        assert!(cursor.is_complete());
    }
}
