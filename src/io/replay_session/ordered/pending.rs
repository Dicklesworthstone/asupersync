//! Optional pending-poll request fingerprints. No payload or provider is owned.

use crate::io::replay::IoOperation;
use sha2::{Digest, Sha256};
use std::{fmt, io::IoSlice};
use zeroize::Zeroize;

/// Independent work bounds for recording I/O polls that return `Pending`.
///
/// Completed I/O still uses `SessionCaptureLimits::io`. The ordering limit also
/// counts pending polls. These bounds limit additional fingerprints/hash work,
/// not the provider's memory or time in a poll. Zero limits are valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingIoCaptureLimits {
    /// Maximum recorded pending polls, including flush/shutdown and empty calls.
    pub max_polls: usize,
    /// Aggregate offered scalar/vectored bytes hashed across pending writes.
    pub max_write_bytes: usize,
    /// Maximum slices in one pending vectored write, including empty slices.
    pub max_vectored_slices: usize,
}

impl PendingIoCaptureLimits {
    /// Set the extra poll, hashing, and vector-shape bounds explicitly.
    #[must_use]
    pub const fn new(max_polls: usize, max_write_bytes: usize, max_vectored_slices: usize) -> Self {
        Self {
            max_polls,
            max_write_bytes,
            max_vectored_slices,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum PendingInput<'a, 'b> {
    Read(usize),
    Write(&'a [u8]),
    Vectored(&'a [IoSlice<'b>]),
    Flush,
    Shutdown,
}

impl PendingInput<'_, '_> {
    pub(super) fn operation(self) -> IoOperation {
        match self {
            Self::Read(_) => IoOperation::Read,
            Self::Write(_) => IoOperation::Write,
            Self::Vectored(_) => IoOperation::WriteVectored,
            Self::Flush => IoOperation::Flush,
            Self::Shutdown => IoOperation::Shutdown,
        }
    }

    pub(super) fn slices(self) -> usize {
        match self {
            Self::Vectored(bufs) => bufs.len(),
            _ => 0,
        }
    }

    pub(super) fn extent(self) -> Option<usize> {
        match self {
            Self::Read(capacity) => Some(capacity),
            Self::Write(bytes) => Some(bytes.len()),
            Self::Vectored(bufs) => bufs
                .iter()
                .try_fold(0usize, |n, buf| n.checked_add(buf.len())),
            Self::Flush | Self::Shutdown => Some(0),
        }
    }

    pub(super) fn is_write(self) -> bool {
        matches!(self, Self::Write(_) | Self::Vectored(_))
    }

    // Called only after bounded admission, without an ordering lock held. The
    // vector count is checked BEFORE walking vector lengths, and the aggregate
    // offered byte count is checked BEFORE hashing any payload.
    pub(super) fn snapshot(self, extent: usize) -> Option<PendingRequest> {
        let mut request = PendingRequest {
            extent,
            slices: self.slices(),
            digest: [0; 32],
        };
        if self.is_write() {
            let mut hash = Sha256::new();
            hash.update(b"asupersync.pending-io.v1");
            hash.update([u8::from(matches!(self, Self::Vectored(_)))]);
            hash.update(u64::try_from(extent).ok()?.to_le_bytes());
            hash.update(u64::try_from(self.slices()).ok()?.to_le_bytes());
            match self {
                Self::Write(bytes) => hash.update(bytes),
                Self::Vectored(bufs) => {
                    for buf in bufs {
                        hash.update(u64::try_from(buf.len()).ok()?.to_le_bytes());
                        hash.update(&buf[..]);
                    }
                }
                _ => unreachable!("write request checked"),
            }
            request.digest = hash.finalize().into();
        }
        Some(request)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct PendingRequest {
    // Read capacity, or total offered write bytes; zero for flush/shutdown.
    pub(super) extent: usize,
    pub(super) slices: usize,
    pub(super) digest: [u8; 32],
}

impl fmt::Debug for PendingRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingRequest")
            .field("extent", &self.extent)
            .field("slices", &self.slices)
            .finish_non_exhaustive()
    }
}

impl Drop for PendingRequest {
    fn drop(&mut self) {
        self.digest.zeroize();
    }
}

impl PendingRequest {
    pub(super) fn valid_for(&self, operation: IoOperation) -> bool {
        match operation {
            IoOperation::Read => self.slices == 0 && self.digest == [0; 32],
            IoOperation::Write => self.slices == 0,
            IoOperation::WriteVectored => self.slices != 0 || self.extent == 0,
            IoOperation::Flush | IoOperation::Shutdown => {
                self.extent == 0 && self.slices == 0 && self.digest == [0; 32]
            }
        }
    }

    pub(super) fn matches(&self, input: PendingInput<'_, '_>) -> bool {
        // Do not walk or hash a changed request outside its admitted shape.
        self.valid_for(input.operation())
            && self.slices == input.slices()
            && input.extent() == Some(self.extent)
            && input.snapshot(self.extent).as_ref() == Some(self)
    }
}
