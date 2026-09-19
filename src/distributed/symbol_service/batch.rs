//! Canonical batches of existing HMAC-authenticated symbols; no new cryptography.

use crate::security::{AuthKey, AuthenticatedSymbol, AuthenticationTag};
use crate::types::symbol::{ObjectId, Symbol, SymbolId, SymbolKind};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroize;

const MAGIC: &[u8; 8] = b"ASUPSYM\0";
const HEADER: usize = 32;
const ENTRY: usize = 42;

/// Explicit per-batch limits, independent of the remote service's frame limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolBatchLimits {
    /// Complete binary encoding, not its enclosing JSON service frame.
    pub max_encoded_bytes: usize,
    /// Maximum symbols; an empty batch is never a successful replication.
    pub max_symbols: usize,
    /// Sum of symbol payload lengths.
    pub max_payload_bytes: usize,
    /// Logical decoded vector and payload storage, excluding allocator overhead.
    pub max_decoded_bytes: usize,
}

/// Exact immutable batch identity. The digest identifies bytes; it authenticates nothing.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolBatchKey {
    /// Object whose symbols are retained.
    pub object_id: ObjectId,
    /// Domain-separated SHA-256 of the complete canonical batch.
    pub digest: [u8; 32],
}

impl fmt::Debug for SymbolBatchKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymbolBatchKey").finish_non_exhaustive()
    }
}

/// Payload-free rejection from batch encoding, verification, or replica storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SymbolStoreError {
    /// Unsupported magic/version, invalid kind, or noncanonical symbol order.
    #[error("invalid symbol batch format")]
    Format,
    /// A declared field extends beyond the complete input.
    #[error("truncated symbol batch")]
    Truncated,
    /// Bytes remain after the declared symbols.
    #[error("trailing symbol batch data")]
    TrailingData,
    /// Empty batches cannot establish storage of an object.
    #[error("empty symbol batch")]
    Empty,
    /// All symbols must belong to one object with distinct block/ESI identities.
    #[error("mixed object or duplicate symbol identity")]
    Identity,
    /// At least one existing symbol tag failed verification under the receiver key.
    #[error("symbol batch authentication failed")]
    Authentication,
    /// Caller-supplied resource bound exceeded.
    #[error("symbol store exceeds its {0} limit")]
    Limit(&'static str),
    /// Arithmetic cannot be represented on the target.
    #[error("symbol batch size overflow")]
    Overflow,
    /// Bounded allocation failed.
    #[error("symbol batch allocation failed")]
    Allocation,
    /// Peer/replica labels must be nonempty and at most 255 UTF-8 bytes.
    #[error("invalid symbol store identity")]
    InvalidIdentity,
    /// An existing peer/object key cannot be replaced with different bytes.
    #[error("immutable symbol batch conflict")]
    Conflict,
    /// No batch with this exact key exists in the authenticated peer's namespace.
    #[error("symbol batch not found")]
    NotFound,
}

/// Owned plaintext wire bytes, redacted in Debug and zeroized on final drop.
/// Copies retained by callers or the remote-service envelope are separate owners.
pub struct EncodedSymbolBatch {
    pub(super) bytes: Vec<u8>,
    pub(super) key: SymbolBatchKey,
    pub(super) count: u32,
}

impl fmt::Debug for EncodedSymbolBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncodedSymbolBatch")
            .field("symbols", &self.count)
            .field("encoded_bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}
impl AsRef<[u8]> for EncodedSymbolBatch {
    fn as_ref(&self) -> &[u8] { &self.bytes }
}
impl Drop for EncodedSymbolBatch {
    fn drop(&mut self) { self.bytes.zeroize(); }
}
impl EncodedSymbolBatch {
    /// Identity used for exact fetches and acknowledgement validation.
    #[must_use]
    pub const fn key(&self) -> SymbolBatchKey { self.key }
    /// Number of distinct retained symbols.
    #[must_use]
    pub const fn symbol_count(&self) -> u32 { self.count }
}

fn add(a: usize, b: usize) -> Result<usize, SymbolStoreError> {
    a.checked_add(b).ok_or(SymbolStoreError::Overflow)
}
fn admitted(count: usize, payload: usize, limits: SymbolBatchLimits) -> Result<usize, SymbolStoreError> {
    if count == 0 { return Err(SymbolStoreError::Empty); }
    if count > limits.max_symbols { return Err(SymbolStoreError::Limit("symbols")); }
    if payload > limits.max_payload_bytes { return Err(SymbolStoreError::Limit("payload bytes")); }
    let storage = add(count.checked_mul(std::mem::size_of::<AuthenticatedSymbol>())
        .ok_or(SymbolStoreError::Overflow)?, payload)?;
    if storage > limits.max_decoded_bytes { return Err(SymbolStoreError::Limit("decoded bytes")); }
    let size = add(add(HEADER, count.checked_mul(ENTRY).ok_or(SymbolStoreError::Overflow)?)?, payload)?;
    if size > limits.max_encoded_bytes { return Err(SymbolStoreError::Limit("encoded bytes")); }
    Ok(size)
}
pub(super) fn key(object_id: ObjectId, bytes: &[u8]) -> SymbolBatchKey {
    let mut hash = Sha256::new();
    hash.update(b"asupersync.symbol-batch.v1");
    hash.update(bytes);
    SymbolBatchKey { object_id, digest: hash.finalize().into() }
}
fn copy(bytes: &[u8]) -> Result<Vec<u8>, SymbolStoreError> {
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len()).map_err(|_| SymbolStoreError::Allocation)?;
    out.extend_from_slice(bytes);
    Ok(out)
}

/// Encode a single object's symbols sorted by (block, ESI), without signing them.
///
/// V1: magic[8], version:u32, object:u128, count:u32, then each symbol's
/// block:u8, ESI:u32, kind:u8 (0=source, 1=repair), length:u32, tag[32], payload.
/// Integers are little-endian. Empty, duplicate and mixed-object batches refuse.
/// Existing tags are preserved, NOT trusted: receivers must call the decoder.
/// Temporary sorting references are bounded by the decoded-storage limit.
pub fn encode_symbol_batch(
    symbols: &[AuthenticatedSymbol], limits: SymbolBatchLimits,
) -> Result<EncodedSymbolBatch, SymbolStoreError> {
    let first = symbols.first().ok_or(SymbolStoreError::Empty)?;
    let object = first.symbol().id().object_id();
    let count = u32::try_from(symbols.len()).map_err(|_| SymbolStoreError::Overflow)?;
    let payload = symbols.iter().try_fold(0usize, |total, symbol| add(total, symbol.symbol().data().len()))?;
    let size = admitted(symbols.len(), payload, limits)?;
    let mut sorted = Vec::new();
    sorted.try_reserve_exact(symbols.len()).map_err(|_| SymbolStoreError::Allocation)?;
    sorted.extend(symbols.iter());
    sorted.sort_unstable_by_key(|symbol| (symbol.symbol().sbn(), symbol.symbol().esi()));
    let mut previous = None;
    for symbol in &sorted {
        let identity = (symbol.symbol().sbn(), symbol.symbol().esi());
        if symbol.symbol().id().object_id() != object || previous == Some(identity) {
            return Err(SymbolStoreError::Identity);
        }
        u32::try_from(symbol.symbol().data().len()).map_err(|_| SymbolStoreError::Overflow)?;
        previous = Some(identity);
    }
    let mut out = EncodedSymbolBatch {
        bytes: Vec::new(), key: SymbolBatchKey { object_id: object, digest: [0; 32] }, count,
    };
    out.bytes.try_reserve_exact(size).map_err(|_| SymbolStoreError::Allocation)?;
    out.bytes.extend_from_slice(MAGIC);
    out.bytes.extend_from_slice(&1_u32.to_le_bytes());
    out.bytes.extend_from_slice(&object.as_u128().to_le_bytes());
    out.bytes.extend_from_slice(&count.to_le_bytes());
    for symbol in sorted {
        let raw = symbol.symbol();
        out.bytes.push(raw.sbn());
        out.bytes.extend_from_slice(&raw.esi().to_le_bytes());
        out.bytes.push(match raw.kind() { SymbolKind::Source => 0, SymbolKind::Repair => 1 });
        out.bytes.extend_from_slice(&(raw.data().len() as u32).to_le_bytes());
        out.bytes.extend_from_slice(symbol.tag().as_bytes());
        out.bytes.extend_from_slice(raw.data());
    }
    out.key = key(object, &out.bytes);
    Ok(out)
}

struct Cursor<'a> { bytes: &'a [u8], offset: usize }
impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], SymbolStoreError> {
        let end = add(self.offset, length)?;
        let value = self.bytes.get(self.offset..end).ok_or(SymbolStoreError::Truncated)?;
        self.offset = end;
        Ok(value)
    }
    fn u32(&mut self) -> Result<u32, SymbolStoreError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("four bytes")))
    }
}

/// Check framing/counts/order before any decoded symbol or payload is allocated.
fn scan(bytes: &[u8], limits: SymbolBatchLimits) -> Result<(ObjectId, u32), SymbolStoreError> {
    if bytes.len() > limits.max_encoded_bytes { return Err(SymbolStoreError::Limit("encoded bytes")); }
    let mut c = Cursor { bytes, offset: 0 };
    if c.take(8)? != MAGIC || c.u32()? != 1 { return Err(SymbolStoreError::Format); }
    let object = ObjectId::from_u128(u128::from_le_bytes(c.take(16)?.try_into().expect("sixteen bytes")));
    let count = c.u32()?;
    let n = usize::try_from(count).map_err(|_| SymbolStoreError::Overflow)?;
    admitted(n, 0, limits)?;
    let mut payload = 0;
    let mut previous = None;
    for _ in 0..count {
        let sbn = c.take(1)?[0];
        let esi = c.u32()?;
        if previous.is_some_and(|old| old >= (sbn, esi)) { return Err(SymbolStoreError::Format); }
        previous = Some((sbn, esi));
        if c.take(1)?[0] > 1 { return Err(SymbolStoreError::Format); }
        let length = usize::try_from(c.u32()?).map_err(|_| SymbolStoreError::Overflow)?;
        payload = add(payload, length)?;
        admitted(n, payload, limits)?;
        c.take(32)?;
        c.take(length)?;
    }
    if c.offset != bytes.len() { return Err(SymbolStoreError::TrailingData); }
    Ok((object, count))
}

/// Verify EVERY symbol with the explicit receiver key, regardless of prior flags.
/// No partially verified vector is returned. Limits bound the full decoded vector.
pub fn decode_symbol_batch(
    bytes: &[u8], auth_key: &AuthKey, limits: SymbolBatchLimits,
) -> Result<Vec<AuthenticatedSymbol>, SymbolStoreError> {
    let (object, count) = scan(bytes, limits)?;
    let mut symbols = Vec::new();
    symbols.try_reserve_exact(count as usize).map_err(|_| SymbolStoreError::Allocation)?;
    let mut c = Cursor { bytes, offset: HEADER };
    for _ in 0..count {
        let sbn = c.take(1)?[0];
        let esi = c.u32()?;
        let kind = if c.take(1)?[0] == 0 { SymbolKind::Source } else { SymbolKind::Repair };
        let length = c.u32()? as usize;
        let tag = AuthenticationTag::from_bytes(c.take(32)?.try_into().expect("tag bytes"));
        let symbol = Symbol::new(SymbolId::new(object, sbn, esi), copy(c.take(length)?)?, kind);
        if !tag.verify(auth_key, &symbol) { return Err(SymbolStoreError::Authentication); }
        symbols.push(AuthenticatedSymbol::new_verified(symbol, tag));
    }
    Ok(symbols)
}

pub(super) fn verified_bytes(
    bytes: &[u8], auth_key: &AuthKey, limits: SymbolBatchLimits,
) -> Result<EncodedSymbolBatch, SymbolStoreError> {
    let symbols = decode_symbol_batch(bytes, auth_key, limits)?;
    let object = symbols[0].symbol().id().object_id();
    let count = symbols.len() as u32;
    drop(symbols);
    Ok(EncodedSymbolBatch { bytes: copy(bytes)?, key: key(object, bytes), count })
}
