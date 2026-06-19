//! RaptorQ `Symbol` ↔ QUIC DATAGRAM bridge (`arq-quic-epic-b0k8qo.2.2` / `.2.3`).
//!
//! The reusable data-path core shared by the B2 sender coroutine and the B3
//! receiver coroutine. It maps a [`Symbol`] to/from a [`QuicSymbolEnvelope`] and
//! moves it over the QUIC datagram plane through the A6 [`QuicConnection`] API
//! ([`QuicConnection::send_datagram`] / [`QuicConnection::recv_datagram`]). The
//! envelope wire format and its conformance live in [`super::symbol_envelope`];
//! this module is the semantic bridge plus the connection glue, deliberately
//! separate from the connect / manifest / spray / feedback coroutine (which
//! remains B2/B3 proper, mirroring how A1/A2 split the frame codec from the
//! connection loop and how the envelope codec was split from the coroutine).
//!
//! # Field mapping
//! A [`Symbol`] carries `(SymbolId { object_id, sbn, esi }, kind, data)`; the
//! envelope carries `(transfer_tag, entry, sbn, esi, is_repair, auth_tag,
//! payload)`. `sbn` / `esi` and the source/repair flag map directly. The
//! envelope wire format does **not** carry `object_id`; it carries
//! `(transfer_tag, entry)` routing instead, which the receiver resolves to the
//! symbol's `object_id` via the transfer manifest. So [`envelope_to_symbol`]
//! takes `object_id` explicitly — the B3 coroutine supplies it from the manifest
//! after reading the envelope's `transfer_tag` / `entry`.
//!
//! # Authentication
//! `auth_tag` is carried verbatim. Computing it (per-symbol HMAC over the symbol
//! via the security context) and verifying it are the caller's responsibility;
//! this bridge only carries the tag and relies on
//! [`QuicSymbolEnvelope::decode`]'s `auth_required` gate to fail closed on a
//! posture mismatch.

use crate::bytes::Bytes;
use crate::cx::Cx;
use crate::net::quic_native::{NativeQuicConnectionError, QuicConnection};
use crate::security::tag::TAG_SIZE;
use crate::types::symbol::{ObjectId, Symbol, SymbolId, SymbolKind};

use super::symbol_envelope::{QuicSymbolEnvelope, QuicSymbolEnvelopeError};

/// Build a [`QuicSymbolEnvelope`] from a [`Symbol`] plus its transfer routing
/// context.
///
/// `transfer_tag` / `entry` come from the manifest, and `auth_tag` comes from
/// the security context when per-symbol auth is in use.
#[must_use]
pub fn symbol_to_envelope(
    symbol: &Symbol,
    transfer_tag: u64,
    entry: u32,
    auth_tag: Option<[u8; TAG_SIZE]>,
) -> QuicSymbolEnvelope {
    QuicSymbolEnvelope {
        transfer_tag,
        entry,
        sbn: symbol.id().sbn(),
        esi: symbol.id().esi(),
        is_repair: matches!(symbol.kind(), SymbolKind::Repair),
        auth_tag,
        payload: Bytes::copy_from_slice(symbol.data()),
    }
}

/// Reconstruct a [`Symbol`] from a decoded [`QuicSymbolEnvelope`].
///
/// `object_id` is supplied by the caller — the receiver resolves it from the
/// transfer manifest using the envelope's `transfer_tag` / `entry`, because the
/// envelope wire format carries manifest routing rather than the object id.
#[must_use]
pub fn envelope_to_symbol(envelope: &QuicSymbolEnvelope, object_id: ObjectId) -> Symbol {
    let kind = if envelope.is_repair {
        SymbolKind::Repair
    } else {
        SymbolKind::Source
    };
    Symbol::from_slice(
        SymbolId::new(object_id, envelope.sbn, envelope.esi),
        &envelope.payload,
        kind,
    )
}

/// Error from the [`Symbol`] ↔ QUIC datagram bridge. Both variants are
/// fail-closed: a malformed/over-posture datagram or a rejecting connection is a
/// typed error, never a silent drop or fake success.
#[derive(Debug)]
pub enum SymbolDatagramError {
    /// Envelope encode/decode failed (wrong magic, short buffer, length
    /// mismatch, auth-posture mismatch, or payload too large).
    Envelope(QuicSymbolEnvelopeError),
    /// The underlying QUIC connection rejected the datagram (not established,
    /// oversize frame, queue backpressure, or cancellation).
    Connection(NativeQuicConnectionError),
}

impl core::fmt::Display for SymbolDatagramError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            // QuicSymbolEnvelopeError implements Display (thiserror);
            // NativeQuicConnectionError is Debug-only, so format it via Debug.
            Self::Envelope(e) => write!(f, "symbol envelope error: {e}"),
            Self::Connection(e) => write!(f, "quic connection error: {e:?}"),
        }
    }
}

impl std::error::Error for SymbolDatagramError {}

impl From<QuicSymbolEnvelopeError> for SymbolDatagramError {
    fn from(err: QuicSymbolEnvelopeError) -> Self {
        Self::Envelope(err)
    }
}

impl From<NativeQuicConnectionError> for SymbolDatagramError {
    fn from(err: NativeQuicConnectionError) -> Self {
        Self::Connection(err)
    }
}

/// Encode `symbol` into a DATAGRAM and queue it on `conn` for transmission.
///
/// # Errors
/// [`SymbolDatagramError::Envelope`] if the symbol payload exceeds the envelope
/// length field, or [`SymbolDatagramError::Connection`] if the connection
/// rejects the datagram (not established, encoded frame oversize, queue
/// backpressure, or `cx` cancelled).
pub fn send_symbol(
    cx: &Cx,
    conn: &mut QuicConnection,
    symbol: &Symbol,
    transfer_tag: u64,
    entry: u32,
    auth_tag: Option<[u8; TAG_SIZE]>,
) -> Result<(), SymbolDatagramError> {
    let envelope = symbol_to_envelope(symbol, transfer_tag, entry, auth_tag);
    let bytes = envelope.encode()?;
    conn.send_datagram(cx, bytes)?;
    Ok(())
}

/// Pop the next received DATAGRAM from `conn` and decode it as a symbol
/// envelope, if one is buffered.
///
/// Returns the decoded [`QuicSymbolEnvelope`] — the caller maps it to a
/// [`Symbol`] with [`envelope_to_symbol`] using the manifest-resolved
/// `object_id` — or `Ok(None)` when no datagram is buffered.
///
/// # Errors
/// [`SymbolDatagramError::Envelope`] if a buffered datagram is not a well-formed
/// (and, when `auth_required`, authenticated) symbol envelope — fail closed.
pub fn recv_symbol_envelope(
    conn: &mut QuicConnection,
    auth_required: bool,
) -> Result<Option<QuicSymbolEnvelope>, SymbolDatagramError> {
    match conn.recv_datagram() {
        Some(bytes) => Ok(Some(QuicSymbolEnvelope::decode_bytes(
            bytes,
            auth_required,
        )?)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sym(object: u128, sbn: u8, esi: u32, repair: bool, data: &[u8]) -> Symbol {
        let kind = if repair {
            SymbolKind::Repair
        } else {
            SymbolKind::Source
        };
        Symbol::from_slice(
            SymbolId::new(ObjectId::from_u128(object), sbn, esi),
            data,
            kind,
        )
    }

    #[test]
    fn symbol_envelope_field_mapping_source_and_repair() {
        // `Symbol`/`SymbolId` do not derive `Debug`, so compare with `==`.
        for repair in [false, true] {
            let s = sym(0xABCD, 3, 42, repair, b"raptorq-symbol-bytes");
            let env = symbol_to_envelope(&s, 0x1122, 7, None);
            assert_eq!(env.sbn, 3);
            assert_eq!(env.esi, 42);
            assert_eq!(env.is_repair, repair);
            assert_eq!(env.transfer_tag, 0x1122);
            assert_eq!(env.entry, 7);
            assert_eq!(env.payload.as_ref(), b"raptorq-symbol-bytes");
            let back = envelope_to_symbol(&env, ObjectId::from_u128(0xABCD));
            assert!(back == s, "symbol round-trips through the envelope mapping");
        }
    }

    #[test]
    fn mapping_survives_wire_encode_decode() {
        let s = sym(1, 0, 0, false, b"abc");
        let env = symbol_to_envelope(&s, 9, 1, None);
        let bytes = env.encode().expect("encode");
        let decoded = QuicSymbolEnvelope::decode(&bytes, false).expect("decode");
        let back = envelope_to_symbol(&decoded, ObjectId::from_u128(1));
        assert_eq!(back, s);
    }

    #[test]
    fn auth_tag_is_carried_through_the_wire() {
        let s = sym(2, 1, 5, true, b"xy");
        let tag = [7u8; TAG_SIZE];
        let env = symbol_to_envelope(&s, 0, 0, Some(tag));
        let bytes = env.encode().expect("encode");
        // auth_required=true must accept an authed envelope and preserve the tag.
        let decoded = QuicSymbolEnvelope::decode(&bytes, true).expect("decode authed");
        assert_eq!(decoded.auth_tag, Some(tag));
    }

    #[test]
    fn empty_payload_symbol_round_trips() {
        let s = sym(3, 0, 0, false, b"");
        let env = symbol_to_envelope(&s, 0, 0, None);
        let bytes = env.encode().expect("encode");
        let decoded = QuicSymbolEnvelope::decode(&bytes, false).expect("decode");
        let back = envelope_to_symbol(&decoded, ObjectId::from_u128(3));
        assert_eq!(back, s);
    }
}
