//! Explicit authenticated encryption for sensitive consumer replay archives.
//!
//! This native-only adapter wraps the existing canonical session format; it
//! never changes that format or falls back to importing plaintext. The complete
//! header and ciphertext are authenticated before a component tape is decoded.
//! Keys, nonce namespaces, expected source/capture identities, storage, and
//! access control are supplied by the caller. No ambient entropy, I/O, runtime,
//! automatic persistence, or key lookup is involved.
//!
//! # Key and nonce ownership
//!
//! Use a dedicated, cryptographically random 256-bit archive key. Each sealer
//! requires a caller-allocated 128-bit nonce prefix UNIQUE FOR THAT KEY across
//! all processes and restarts. A freshly generated key may use any prefix. Do
//! not derive prefixes from replayable entropy, clocks, task IDs or process IDs.
//! A sealer is not cloneable or serializable; it consumes an increasing 64-bit
//! counter before encryption and refuses exhaustion instead of wrapping. These
//! local checks cannot prevent a caller from recreating a key/prefix pair.
//!
//! Encryption does not attest the producer's code, prevent rollback of an
//! authenticated archive, or redact data from an authorized reader. Bind a
//! trusted expected source/configuration fingerprint and unique capture ID when
//! opening. Header identities and payload length are public. Original tapes,
//! caller copies, files and swap remain outside these zeroizing byte owners.

use super::replay_session::{RecordedSession, SessionDecodeLimits, SessionTapeError};
use super::replay_session::ordered::{
    OrderedRecordedSession, OrderedSessionDecodeLimits, OrderedSessionTapeError,
};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use std::fmt;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"ASUPENC\0";
const VERSION: u32 = 1;
const HEADER: usize = 112;
const TAG: usize = 16;
const OVERHEAD: usize = HEADER + TAG;
const SESSION: u8 = 1;
const ORDERED: u8 = 2;

/// Expected external identity of a replay archive. These are public commitments,
/// not secret values or attestations. Compare against trusted caller metadata,
/// not identities copied from the untrusted envelope being opened.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReplayArchiveBinding {
    /// Caller-defined fingerprint of source/build/configuration and capture scope.
    pub source: [u8; 32],
    /// Caller-defined unique capture identity, e.g. a digest of an incident ID.
    pub capture: [u8; 32],
}

impl fmt::Debug for ReplayArchiveBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayArchiveBinding").finish_non_exhaustive()
    }
}

/// Redacted refusal. No variant contains keys, plaintext, digests or identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReplayArchiveError {
    /// Not this encrypted format/version/profile, or nonzero reserved flags.
    #[error("unsupported encrypted replay archive format")]
    Format,
    /// Truncated, extra, overflowing or unrepresentable envelope length.
    #[error("invalid encrypted replay archive length")]
    Length,
    /// The entire ciphertext envelope exceeds the caller's bound.
    #[error("encrypted replay archive exceeds its byte limit")]
    EncodedLimit,
    /// The authenticated plaintext would exceed its independently selected bound.
    #[error("replay archive plaintext exceeds its byte limit")]
    PlaintextLimit,
    /// Wrong key, expected identity, or altered authenticated bytes.
    #[error("encrypted replay archive authentication failed")]
    Authentication,
    /// A sealer cannot issue another unique nonce in this namespace.
    #[error("replay archive nonce sequence exhausted")]
    NonceExhausted,
    /// Bounded output/decryption storage could not be reserved.
    #[error("replay archive allocation failed")]
    Allocation,
    /// The cipher refused an operation. No output is returned or nonce reused.
    #[error("replay archive encryption failed")]
    Encryption,
    /// Authenticated bytes failed the existing canonical session validator.
    #[error("replay archive session: {0}")]
    Session(#[from] SessionTapeError),
    /// Authenticated bytes failed the existing ordered/poll-aware validator.
    #[error("replay archive ordered session: {0}")]
    Ordered(#[from] OrderedSessionTapeError),
}

/// Caller-owned dedicated symmetric key, zeroized on drop and omitted from Debug.
/// No Clone, serialization, generation, global registry or implicit key lookup.
pub struct ReplayArchiveKey {
    bytes: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for ReplayArchiveKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayArchiveKey").finish_non_exhaustive()
    }
}

impl ReplayArchiveKey {
    /// Adopt key bytes from the caller's secure key-management boundary.
    /// Copies retained by that boundary are not erased by this owner.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes: Zeroizing::new(bytes) }
    }

    /// Consume this key into one non-cloneable, non-wrapping nonce namespace.
    ///
    /// The prefix MUST be unique for this key across all sealers/processes and
    /// restarts. Do not recreate a previous key/prefix pair after a crash. Prefer
    /// a fresh key per sealer or an independently durable namespace allocator.
    #[must_use]
    pub fn into_sealer(self, unique_nonce_prefix: [u8; 16]) -> ReplayArchiveSealer {
        ReplayArchiveSealer { key: self, prefix: unique_nonce_prefix, next: Some(0) }
    }

    /// Authenticate and decrypt, then run every existing session/component limit.
    ///
    /// The encrypted and plaintext byte limits are checked before allocating.
    /// No tape decoder or replay provider sees unauthenticated bytes. Scratch
    /// plaintext is zeroized on success, refusal or unwinding. This synchronous
    /// operation performs work proportional to the admitted encoding; it does
    /// not claim an async cancellation or wall-clock bound.
    pub fn open_session(
        &self,
        bytes: &[u8],
        expected: ReplayArchiveBinding,
        max_encrypted_bytes: usize,
        limits: SessionDecodeLimits,
    ) -> Result<RecordedSession, ReplayArchiveError> {
        let plaintext = self.open_payload(bytes, expected, SESSION, max_encrypted_bytes, limits.max_encoded_bytes)?;
        Ok(RecordedSession::from_canonical_bytes(&plaintext, limits)?)
    }

    /// Authenticate an ordered archive without discarding its order or pending polls.
    ///
    /// Both existing completed-effect V1 and poll-aware V2 formats remain valid.
    /// Use `open_poll_aware` when the application REQUIRES pending-poll fidelity.
    /// The separate authenticated profile refuses an independent session rather
    /// than silently treating it as an ordered replay. All nested bounds apply.
    pub fn open_ordered(
        &self,
        bytes: &[u8],
        expected: ReplayArchiveBinding,
        max_encrypted_bytes: usize,
        limits: OrderedSessionDecodeLimits,
    ) -> Result<OrderedRecordedSession, ReplayArchiveError> {
        let plaintext = self.open_payload(bytes, expected, ORDERED, max_encrypted_bytes, limits.max_encoded_bytes)?;
        Ok(OrderedRecordedSession::from_canonical_bytes(&plaintext, limits)?)
    }

    /// Authenticate and REQUIRE poll-aware V2 data. A validly encrypted V1 tape
    /// is still refused; authentication cannot weaken the caller's fidelity need.
    /// This retains pending request shapes, not the original wake timing.
    pub fn open_poll_aware(
        &self,
        bytes: &[u8],
        expected: ReplayArchiveBinding,
        max_encrypted_bytes: usize,
        limits: OrderedSessionDecodeLimits,
    ) -> Result<OrderedRecordedSession, ReplayArchiveError> {
        let plaintext = self.open_payload(bytes, expected, ORDERED, max_encrypted_bytes, limits.max_encoded_bytes)?;
        Ok(OrderedRecordedSession::from_poll_aware_bytes(&plaintext, limits)?)
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new_from_slice(self.bytes.as_ref())
            .expect("archive key has the cipher's fixed 32-byte size")
    }

    fn open_payload(
        &self,
        bytes: &[u8],
        expected: ReplayArchiveBinding,
        profile: u8,
        max_encrypted_bytes: usize,
        max_plaintext_bytes: usize,
    ) -> Result<Zeroizing<Vec<u8>>, ReplayArchiveError> {
        if bytes.len() > max_encrypted_bytes { return Err(ReplayArchiveError::EncodedLimit); }
        if bytes.len() < OVERHEAD { return Err(ReplayArchiveError::Length); }
        if &bytes[..8] != MAGIC || bytes[8..12] != VERSION.to_le_bytes()
            || bytes[12] != profile || bytes[13..16] != [0; 3]
        {
            return Err(ReplayArchiveError::Format);
        }
        let declared = u64::from_le_bytes(bytes[16..24].try_into().expect("fixed length field"));
        let length = usize::try_from(declared).map_err(|_| ReplayArchiveError::Length)?;
        if length.checked_add(OVERHEAD) != Some(bytes.len()) { return Err(ReplayArchiveError::Length); }
        if length > max_plaintext_bytes { return Err(ReplayArchiveError::PlaintextLimit); }
        // Identities are public. Fail early without allocating; changing either
        // the stored identity or expected identity can never bypass the AEAD.
        if bytes[48..80] != expected.source || bytes[80..HEADER] != expected.capture {
            return Err(ReplayArchiveError::Authentication);
        }
        let end = HEADER + length; // checked by the exact total-length comparison
        let nonce = XNonce::try_from(&bytes[24..48]).expect("fixed 24-byte nonce field");
        let tag = Tag::try_from(&bytes[end..]).expect("fixed 16-byte authentication tag");
        let mut plaintext = Zeroizing::new(Vec::new());
        plaintext.try_reserve_exact(length).map_err(|_| ReplayArchiveError::Allocation)?;
        plaintext.extend_from_slice(&bytes[HEADER..end]);
        self.cipher().decrypt_inout_detached(
            &nonce, &bytes[..HEADER], plaintext.as_mut_slice().into(), &tag,
        ).map_err(|_| ReplayArchiveError::Authentication)?;
        Ok(plaintext)
    }
}

/// Exclusive encryption owner. The counter is burned before calling the cipher,
/// including failed encryption; neither Clone nor counter restoration is exposed.
pub struct ReplayArchiveSealer {
    key: ReplayArchiveKey,
    prefix: [u8; 16],
    next: Option<u64>,
}

impl fmt::Debug for ReplayArchiveSealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayArchiveSealer")
            .field("exhausted", &self.next.is_none()).finish_non_exhaustive()
    }
}

impl ReplayArchiveSealer {
    /// Export a complete session directly into an authenticated ciphertext owner.
    ///
    /// `max_encrypted_bytes` includes the 112-byte header and 16-byte tag. The
    /// shrinking bound reaches the existing component encoders before allocation.
    /// The original tape is borrowed and preserved on every path. Temporary
    /// canonical plaintext and encryption scratch zeroize when retired. Peak
    /// logical encoded storage includes both buffers, not just the final result.
    pub fn seal_session(
        &mut self,
        session: &RecordedSession,
        binding: ReplayArchiveBinding,
        max_encrypted_bytes: usize,
    ) -> Result<EncryptedReplayArchive, ReplayArchiveError> {
        let limit = self.plaintext_limit(max_encrypted_bytes)?;
        let plaintext = session.to_canonical_bytes(limit)?;
        self.seal_payload(plaintext.as_ref(), binding, SESSION, max_encrypted_bytes)
    }

    /// Encrypt an ordered or poll-aware capture without changing its canonical
    /// version, sequencing authority or pending request fingerprints. Ordinary
    /// and ordered seals share THIS sealer's one nonce counter and key namespace.
    pub fn seal_ordered(
        &mut self,
        session: &OrderedRecordedSession,
        binding: ReplayArchiveBinding,
        max_encrypted_bytes: usize,
    ) -> Result<EncryptedReplayArchive, ReplayArchiveError> {
        let limit = self.plaintext_limit(max_encrypted_bytes)?;
        let plaintext = session.to_canonical_bytes(limit)?;
        self.seal_payload(plaintext.as_ref(), binding, ORDERED, max_encrypted_bytes)
    }

    fn plaintext_limit(&self, max_encrypted_bytes: usize) -> Result<usize, ReplayArchiveError> {
        if self.next.is_none() { return Err(ReplayArchiveError::NonceExhausted); }
        max_encrypted_bytes.checked_sub(OVERHEAD).ok_or(ReplayArchiveError::EncodedLimit)
    }

    fn take_nonce(&mut self) -> Result<[u8; 24], ReplayArchiveError> {
        let counter = self.next.ok_or(ReplayArchiveError::NonceExhausted)?;
        self.next = counter.checked_add(1);
        let mut nonce = [0; 24];
        nonce[..16].copy_from_slice(&self.prefix);
        nonce[16..].copy_from_slice(&counter.to_le_bytes());
        Ok(nonce)
    }

    fn seal_payload(
        &mut self,
        plaintext: &[u8],
        binding: ReplayArchiveBinding,
        profile: u8,
        max_encrypted_bytes: usize,
    ) -> Result<EncryptedReplayArchive, ReplayArchiveError> {
        let limit = self.plaintext_limit(max_encrypted_bytes)?;
        if plaintext.len() > limit { return Err(ReplayArchiveError::EncodedLimit); }
        let size = plaintext.len().checked_add(OVERHEAD).ok_or(ReplayArchiveError::Length)?;
        let length = u64::try_from(plaintext.len()).map_err(|_| ReplayArchiveError::Length)?;
        let mut out = EncryptedReplayArchive(Zeroizing::new(Vec::new()));
        out.0.try_reserve_exact(size).map_err(|_| ReplayArchiveError::Allocation)?;
        let nonce_bytes = self.take_nonce()?;
        out.0.extend_from_slice(MAGIC);
        out.0.extend_from_slice(&VERSION.to_le_bytes());
        out.0.push(profile);
        out.0.extend_from_slice(&[0; 3]);
        out.0.extend_from_slice(&length.to_le_bytes());
        out.0.extend_from_slice(&nonce_bytes);
        out.0.extend_from_slice(&binding.source);
        out.0.extend_from_slice(&binding.capture);
        out.0.extend_from_slice(plaintext);
        let nonce = XNonce::try_from(nonce_bytes.as_slice()).expect("fixed 24-byte nonce");
        let (header, payload) = out.0.split_at_mut(HEADER);
        let tag = self.key.cipher().encrypt_inout_detached(&nonce, header, payload.into())
            .map_err(|_| ReplayArchiveError::Encryption)?;
        out.0.extend_from_slice(&tag);
        debug_assert_eq!(out.0.len(), size);
        Ok(out)
    }
}

/// Ciphertext ready for caller-controlled storage/transport, not an implicitly
/// persisted file. Debug is size-only; temporary plaintext in this owner is
/// zeroized even when sealing fails. Caller copies are outside its ownership.
pub struct EncryptedReplayArchive(Zeroizing<Vec<u8>>);

impl fmt::Debug for EncryptedReplayArchive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedReplayArchive")
            .field("encrypted_bytes", &self.0.len()).finish_non_exhaustive()
    }
}

impl AsRef<[u8]> for EncryptedReplayArchive {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

#[cfg(test)]
mod tests;
