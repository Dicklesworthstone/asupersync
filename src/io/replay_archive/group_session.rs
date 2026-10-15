//! Authenticated, all-or-nothing joint multi-stream/clock/entropy archives.
use super::{EncryptedReplayArchive, ReplayArchiveBinding, ReplayArchiveError, ReplayArchiveKey, ReplayArchiveSealer};
use crate::io::replay_group_session::{GroupSessionDecodeLimits, GroupSessionTapeError, RecordedGroupSession};

// Profile four is distinct from independent sessions, ordered single-stream
// sessions, and byte-only groups. The complete header is authenticated.
const GROUP_SESSION: u8 = 4;

/// Envelope authentication refusal and authenticated tape refusal are distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GroupSessionArchiveError {
    /// No component tape has been accepted on this path.
    #[error(transparent)]
    Archive(#[from] ReplayArchiveError),
    /// Authenticated bytes failed bounded joint-window decoding.
    #[error(transparent)]
    Tape(#[from] GroupSessionTapeError),
}

impl ReplayArchiveSealer {
    /// Seal all streams, clock, entropy forks and cross-provider order together.
    /// Shares this sealer's single non-wrapping nonce sequence with every other
    /// profile. The existing caller-owned key/prefix uniqueness requirements apply.
    /// No plaintext file, source lookup, network call or implicit key exists here.
    pub fn seal_group_session(
        &mut self,
        session: &RecordedGroupSession,
        binding: ReplayArchiveBinding,
        max_encrypted_bytes: usize,
    ) -> Result<EncryptedReplayArchive, GroupSessionArchiveError> {
        let limit = self.plaintext_limit(max_encrypted_bytes)?;
        let plaintext = session.to_canonical_bytes(limit)?;
        Ok(self.seal_payload(plaintext.as_ref(), binding, GROUP_SESSION, max_encrypted_bytes)?)
    }
}
impl ReplayArchiveKey {
    /// Authenticate the complete envelope before any nested tape is decoded.
    /// Byte-only groups and single-stream sessions cannot substitute for this
    /// profile. Expected bindings must come from independently trusted metadata,
    /// not the untrusted header. Every group/component bound remains enforced.
    pub fn open_group_session(
        &self,
        bytes: &[u8],
        expected: ReplayArchiveBinding,
        max_encrypted_bytes: usize,
        limits: GroupSessionDecodeLimits,
    ) -> Result<RecordedGroupSession, GroupSessionArchiveError> {
        let plaintext = self.open_payload(bytes, expected, GROUP_SESSION, max_encrypted_bytes, limits.max_encoded_bytes)?;
        Ok(RecordedGroupSession::from_canonical_bytes(&plaintext, limits)?)
    }
}

#[cfg(test)]
mod tests;
