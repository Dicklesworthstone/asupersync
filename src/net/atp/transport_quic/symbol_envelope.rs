//! RaptorQ symbol envelope for the ATP-over-QUIC data plane.
//!
//! A single RaptorQ symbol is carried inside one QUIC DATAGRAM frame (RFC 9221).
//! This module owns the application-level framing of that symbol — the header
//! that lets the receiver route the symbol to the right transfer, file entry,
//! source block, and encoding-symbol id, plus an optional per-symbol
//! authentication tag — independent of the QUIC frame/packet layer (which is
//! specified in `docs/quic_wire_format.md`).
//!
//! The schema deliberately mirrors the proven `transport_rq` UDP symbol datagram
//! (`crate::net::atp::transport_rq`) so the RaptorQ-over-QUIC and RaptorQ-over-UDP
//! data planes commit to the same symbol-routing fields. The only difference is
//! the magic (`"ATQS"` vs `transport_rq`'s `"ATRQ"`) so a misdelivered datagram
//! from the wrong transport fails closed instead of being misparsed.
//!
//! # Wire layout (big-endian)
//!
//! ```text
//! offset  size  field
//!   0      4    magic = 0x41545153 ("ATQS")
//!   4      8    transfer_tag (u64)      — demuxes transfers on a reused connection
//!  12      4    entry        (u32)      — manifest entry index
//!  16      1    sbn          (u8)       — RaptorQ source block number
//!  17      4    esi          (u32)      — RaptorQ encoding symbol id
//!  21      1    repair       (u8: 0|1)  — 0 = source symbol, 1 = repair symbol
//!  22      2    payload_len  (u16)      — symbol payload length
//!  24     32    auth_tag     (optional) — present iff the receiver requires auth
//!  ..      N    payload                 — exactly payload_len bytes
//! ```
//!
//! Decoding is **fail closed and total**: it never panics on arbitrary input and
//! rejects a wrong magic, a short buffer, a declared length that does not match
//! the datagram, an out-of-range repair flag, or an oversize payload.
//!
//! This is the foundational codec for B2/B3 (`asupersync-arq-quic-epic-b0k8qo.2.2`
//! / `.2.3`); the sender/receiver coroutines map a `crate::types::symbol::Symbol`
//! to/from these fields and call [`QuicSymbolEnvelope::encode`] /
//! [`QuicSymbolEnvelope::decode`].

use crate::bytes::Bytes;
use crate::security::tag::TAG_SIZE;

/// Magic prefix on every ATP-over-QUIC symbol envelope (`"ATQS"`).
pub const ATP_QUIC_SYMBOL_MAGIC: u32 = 0x4154_5153;

/// Fixed header length (magic + transfer_tag + entry + sbn + esi + repair +
/// payload_len), big-endian. The authentication tag and payload follow.
pub const ENVELOPE_HEADER_LEN: usize = 4 + 8 + 4 + 1 + 4 + 1 + 2;

/// Header length when a per-symbol authentication tag is present.
pub const AUTH_ENVELOPE_HEADER_LEN: usize = ENVELOPE_HEADER_LEN + TAG_SIZE;

/// Errors from [`QuicSymbolEnvelope`] encode/decode. Every decode failure is a
/// fail-closed rejection of malformed/foreign input — never a panic.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QuicSymbolEnvelopeError {
    /// The buffer is shorter than the header it must contain.
    #[error("symbol envelope too short: have {have} bytes, need at least {need}")]
    TooShort {
        /// Bytes available.
        have: usize,
        /// Bytes required for the header.
        need: usize,
    },
    /// The magic prefix did not match [`ATP_QUIC_SYMBOL_MAGIC`].
    #[error(
        "symbol envelope bad magic: found {found:#010x}, expected {ATP_QUIC_SYMBOL_MAGIC:#010x}"
    )]
    BadMagic {
        /// The magic actually read.
        found: u32,
    },
    /// The repair flag byte was neither 0 nor 1.
    #[error("symbol envelope invalid repair flag byte: {byte}")]
    InvalidRepairFlag {
        /// The out-of-range byte.
        byte: u8,
    },
    /// The declared payload length did not match the bytes actually present.
    #[error("symbol envelope length mismatch: declared {declared}, available {available}")]
    LengthMismatch {
        /// `payload_len` from the header.
        declared: usize,
        /// Bytes available after the header.
        available: usize,
    },
    /// The payload is larger than the `u16` length field can encode.
    #[error("symbol payload too large to encode: {len} bytes (max {max})", max = u16::MAX)]
    PayloadTooLarge {
        /// The oversize payload length.
        len: usize,
    },
}

/// A RaptorQ symbol plus its routing/authentication header, as carried in a
/// single QUIC DATAGRAM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicSymbolEnvelope {
    /// Transfer tag, demuxing transfers multiplexed on a reused connection.
    pub transfer_tag: u64,
    /// Manifest entry index this symbol belongs to.
    pub entry: u32,
    /// RaptorQ source block number.
    pub sbn: u8,
    /// RaptorQ encoding symbol id.
    pub esi: u32,
    /// Whether this is a repair (`true`) or source (`false`) symbol.
    pub is_repair: bool,
    /// Optional per-symbol authentication tag.
    pub auth_tag: Option<[u8; TAG_SIZE]>,
    /// The symbol payload.
    pub payload: Bytes,
}

impl QuicSymbolEnvelope {
    /// Header length for this envelope (accounts for the optional auth tag).
    #[must_use]
    pub fn header_len(&self) -> usize {
        if self.auth_tag.is_some() {
            AUTH_ENVELOPE_HEADER_LEN
        } else {
            ENVELOPE_HEADER_LEN
        }
    }

    /// Total encoded size in bytes (header + optional tag + payload).
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.header_len() + self.payload.len()
    }

    /// Encode the envelope to a single contiguous DATAGRAM payload.
    ///
    /// Fails closed if the payload is larger than the `u16` length field allows
    /// (RaptorQ symbols are bounded well under this by `QuicConfig::symbol_size`).
    pub fn encode(&self) -> Result<Bytes, QuicSymbolEnvelopeError> {
        let payload_len = u16::try_from(self.payload.len()).map_err(|_| {
            QuicSymbolEnvelopeError::PayloadTooLarge {
                len: self.payload.len(),
            }
        })?;

        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(&ATP_QUIC_SYMBOL_MAGIC.to_be_bytes());
        out.extend_from_slice(&self.transfer_tag.to_be_bytes());
        out.extend_from_slice(&self.entry.to_be_bytes());
        out.push(self.sbn);
        out.extend_from_slice(&self.esi.to_be_bytes());
        out.push(u8::from(self.is_repair));
        out.extend_from_slice(&payload_len.to_be_bytes());
        if let Some(tag) = &self.auth_tag {
            out.extend_from_slice(tag);
        }
        out.extend_from_slice(&self.payload);
        Ok(Bytes::from(out))
    }

    /// Decode an envelope from a complete DATAGRAM payload.
    ///
    /// `auth_required` selects whether a 32-byte authentication tag is expected
    /// between the header and the payload; it must match the receiver's posture
    /// so an authenticated/unauthenticated mismatch fails closed rather than
    /// silently misparsing the payload.
    pub fn decode(buf: &[u8], auth_required: bool) -> Result<Self, QuicSymbolEnvelopeError> {
        let header_len = if auth_required {
            AUTH_ENVELOPE_HEADER_LEN
        } else {
            ENVELOPE_HEADER_LEN
        };
        if buf.len() < header_len {
            return Err(QuicSymbolEnvelopeError::TooShort {
                have: buf.len(),
                need: header_len,
            });
        }

        let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != ATP_QUIC_SYMBOL_MAGIC {
            return Err(QuicSymbolEnvelopeError::BadMagic { found: magic });
        }

        let transfer_tag = u64::from_be_bytes([
            buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
        ]);
        let entry = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let sbn = buf[16];
        let esi = u32::from_be_bytes([buf[17], buf[18], buf[19], buf[20]]);
        let is_repair = match buf[21] {
            0 => false,
            1 => true,
            byte => return Err(QuicSymbolEnvelopeError::InvalidRepairFlag { byte }),
        };
        let declared = usize::from(u16::from_be_bytes([buf[22], buf[23]]));

        let available = buf.len() - header_len;
        if declared != available {
            return Err(QuicSymbolEnvelopeError::LengthMismatch {
                declared,
                available,
            });
        }

        let auth_tag = if auth_required {
            let mut tag = [0u8; TAG_SIZE];
            tag.copy_from_slice(&buf[ENVELOPE_HEADER_LEN..AUTH_ENVELOPE_HEADER_LEN]);
            Some(tag)
        } else {
            None
        };

        let payload = Bytes::copy_from_slice(&buf[header_len..]);

        Ok(Self {
            transfer_tag,
            entry,
            sbn,
            esi,
            is_repair,
            auth_tag,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(auth: bool) -> QuicSymbolEnvelope {
        QuicSymbolEnvelope {
            transfer_tag: 0x0102_0304_0506_0708,
            entry: 7,
            sbn: 3,
            esi: 12345,
            is_repair: true,
            auth_tag: auth.then_some([0xABu8; TAG_SIZE]),
            payload: Bytes::from_static(b"the-raptorq-symbol-bytes"),
        }
    }

    #[test]
    fn roundtrip_without_auth() {
        let env = sample(false);
        let bytes = env.encode().unwrap();
        assert_eq!(bytes.len(), env.encoded_len());
        let back = QuicSymbolEnvelope::decode(&bytes, false).unwrap();
        assert_eq!(env, back);
    }

    #[test]
    fn roundtrip_with_auth() {
        let env = sample(true);
        let bytes = env.encode().unwrap();
        assert_eq!(bytes.len(), AUTH_ENVELOPE_HEADER_LEN + env.payload.len());
        let back = QuicSymbolEnvelope::decode(&bytes, true).unwrap();
        assert_eq!(env, back);
        assert_eq!(back.auth_tag, Some([0xABu8; TAG_SIZE]));
    }

    #[test]
    fn header_layout_is_golden() {
        let env = sample(false);
        let b = env.encode().unwrap();
        assert_eq!(&b[0..4], &ATP_QUIC_SYMBOL_MAGIC.to_be_bytes());
        assert_eq!(&b[4..12], &0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(&b[12..16], &7u32.to_be_bytes());
        assert_eq!(b[16], 3); // sbn
        assert_eq!(&b[17..21], &12345u32.to_be_bytes());
        assert_eq!(b[21], 1); // repair
        assert_eq!(&b[22..24], &(env.payload.len() as u16).to_be_bytes());
        assert_eq!(&b[ENVELOPE_HEADER_LEN..], env.payload.as_ref());
    }

    #[test]
    fn empty_payload_roundtrips() {
        let mut env = sample(false);
        env.payload = Bytes::new();
        let b = env.encode().unwrap();
        assert_eq!(b.len(), ENVELOPE_HEADER_LEN);
        assert_eq!(QuicSymbolEnvelope::decode(&b, false).unwrap(), env);
    }

    #[test]
    fn decode_rejects_short_buffer() {
        let err = QuicSymbolEnvelope::decode(&[0u8; 10], false).unwrap_err();
        assert!(
            matches!(err, QuicSymbolEnvelopeError::TooShort { need, .. } if need == ENVELOPE_HEADER_LEN)
        );
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut b = sample(false).encode().unwrap().to_vec();
        b[0] ^= 0xFF;
        assert!(matches!(
            QuicSymbolEnvelope::decode(&b, false),
            Err(QuicSymbolEnvelopeError::BadMagic { .. })
        ));
    }

    #[test]
    fn decode_rejects_length_mismatch() {
        let b = sample(false).encode().unwrap();
        // Drop the last payload byte: declared length no longer matches.
        let truncated = &b[..b.len() - 1];
        assert!(matches!(
            QuicSymbolEnvelope::decode(truncated, false),
            Err(QuicSymbolEnvelopeError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn decode_rejects_invalid_repair_flag() {
        let mut b = sample(false).encode().unwrap().to_vec();
        b[21] = 2;
        assert!(matches!(
            QuicSymbolEnvelope::decode(&b, false),
            Err(QuicSymbolEnvelopeError::InvalidRepairFlag { byte: 2 })
        ));
    }

    #[test]
    fn auth_posture_mismatch_fails_closed() {
        // Encoded WITH auth but decoded as unauthenticated: the 32 tag bytes are
        // counted as payload, so the declared length no longer matches.
        let b = sample(true).encode().unwrap();
        assert!(QuicSymbolEnvelope::decode(&b, false).is_err());
        // Encoded WITHOUT auth but decoded as requiring auth: too short / mismatch.
        let b2 = sample(false).encode().unwrap();
        assert!(QuicSymbolEnvelope::decode(&b2, true).is_err());
    }

    #[test]
    fn metamorphic_field_change_changes_bytes() {
        let base = sample(false).encode().unwrap();
        let mut other = sample(false);
        other.esi += 1;
        assert_ne!(base, other.encode().unwrap());
    }
}
