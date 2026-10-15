//! Separate authenticated profile for multi-stream I/O observation groups.

use super::{EncryptedReplayArchive, ReplayArchiveBinding, ReplayArchiveError, ReplayArchiveKey, ReplayArchiveSealer};
use crate::io::replay_group::{IoGroupDecodeLimits, IoGroupTapeError, RecordedIoGroup};

// Profile identity is authenticated with the same fixed V1 envelope header.
// Existing independent and ordered profile bytes are unchanged.
const IO_GROUP: u8 = 3;

/// Authentication/size refusal and authenticated group-decoder refusal are distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IoGroupArchiveError {
    /// Original encrypted-envelope refusal; no tape decoder has accepted data.
    #[error(transparent)]
    Archive(#[from] ReplayArchiveError),
    /// Original bounded multi-stream tape refusal after authentication.
    #[error(transparent)]
    Tape(#[from] IoGroupTapeError),
}

impl ReplayArchiveSealer {
    /// Encrypt a complete multi-stream group without dropping identities or order.
    /// The group profile shares this sealer's ONE nonce counter with every other
    /// profile. Existing key/prefix uniqueness and memory boundaries still apply.
    /// No per-stream encrypted files, plaintext output or partial group escapes.
    pub fn seal_io_group(
        &mut self,
        group: &RecordedIoGroup,
        binding: ReplayArchiveBinding,
        max_encrypted_bytes: usize,
    ) -> Result<EncryptedReplayArchive, IoGroupArchiveError> {
        let limit = self.plaintext_limit(max_encrypted_bytes)?;
        let plaintext = group.to_canonical_bytes(limit)?;
        Ok(self.seal_payload(plaintext.as_ref(), binding, IO_GROUP, max_encrypted_bytes)?)
    }
}

impl ReplayArchiveKey {
    /// Authenticate the entire group before applying its independent import bounds.
    /// A single-stream or ordered-session archive is not accepted as a group.
    /// Expected source and capture bindings come from trusted caller metadata,
    /// never from untrusted header fields. Scratch plaintext is zeroized.
    pub fn open_io_group(
        &self,
        bytes: &[u8],
        expected: ReplayArchiveBinding,
        max_encrypted_bytes: usize,
        limits: IoGroupDecodeLimits,
    ) -> Result<RecordedIoGroup, IoGroupArchiveError> {
        let plaintext = self.open_payload(bytes, expected, IO_GROUP, max_encrypted_bytes, limits.max_encoded_bytes)?;
        Ok(RecordedIoGroup::from_canonical_bytes(&plaintext, limits)?)
    }
}

#[cfg(test)]
mod tests;
