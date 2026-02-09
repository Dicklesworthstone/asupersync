//! Unix socket ancillary data for file descriptor passing.
//!
//! This module is implemented in terms of `nix::sys::socket::{sendmsg, recvmsg}` so the
//! rest of the crate does not need to use `unsafe` for control-message plumbing.
//!
//! # Notes
//!
//! - This API is intentionally small: Asupersync currently exposes `SCM_RIGHTS` for FD passing.
//! - When receiving, the ancillary buffer capacity determines how many control messages can be
//!   captured. If it is too small, truncation is reported via [`SocketAncillary::is_truncated`].

use smallvec::SmallVec;
use std::os::unix::io::RawFd;

/// Buffer and bookkeeping for Unix socket ancillary data.
///
/// This type is used for both sending and receiving `SCM_RIGHTS` messages.
/// For receiving, it owns a `Vec<u8>` that is passed to `recvmsg`.
#[derive(Debug, Default)]
pub struct SocketAncillary {
    /// Capacity-only buffer used by `recvmsg`. Length is always kept at 0.
    recv_buf: Vec<u8>,
    /// File descriptors queued for sending.
    send_fds: SmallVec<[RawFd; 8]>,
    /// File descriptors received from the last `recvmsg`.
    recv_fds: SmallVec<[RawFd; 8]>,
    truncated: bool,
}

impl SocketAncillary {
    /// Create a new ancillary container with a given receive-buffer capacity (bytes).
    ///
    /// For a few file descriptors, a capacity like 128 bytes is typically sufficient.
    #[must_use]
    pub fn new(recv_capacity: usize) -> Self {
        Self {
            recv_buf: Vec::with_capacity(recv_capacity),
            send_fds: SmallVec::new(),
            recv_fds: SmallVec::new(),
            truncated: false,
        }
    }

    /// Returns the receive-buffer capacity (bytes).
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.recv_buf.capacity()
    }

    /// Returns `true` if no send fds are queued and no received fds are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.send_fds.is_empty() && self.recv_fds.is_empty()
    }

    /// Returns `true` if the last receive indicated control-message truncation.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Clears all queued and received ancillary state.
    pub fn clear(&mut self) {
        self.send_fds.clear();
        self.recv_fds.clear();
        self.truncated = false;
        // Keep capacity; ensure length is 0.
        self.recv_buf.clear();
    }

    /// Adds file descriptors to be sent via `SCM_RIGHTS`.
    ///
    /// Returns `true` (there is no fixed buffer limit on the send side; `sendmsg` builds the
    /// control-message buffer internally).
    pub fn add_fds(&mut self, fds: &[RawFd]) -> bool {
        self.send_fds.extend_from_slice(fds);
        true
    }

    /// Returns an iterator over received ancillary messages.
    #[must_use]
    pub fn messages(&self) -> AncillaryMessages<'_> {
        AncillaryMessages {
            yielded: false,
            recv_fds: &self.recv_fds,
        }
    }

    pub(crate) fn send_fds(&self) -> &[RawFd] {
        &self.send_fds
    }

    pub(crate) fn clear_send_fds(&mut self) {
        self.send_fds.clear();
    }

    pub(crate) fn prepare_for_recv(&mut self) -> &mut Vec<u8> {
        self.recv_fds.clear();
        self.truncated = false;
        self.recv_buf.clear();
        &mut self.recv_buf
    }

    pub(crate) fn push_received_fds(&mut self, fds: &[RawFd]) {
        self.recv_fds.extend_from_slice(fds);
    }

    pub(crate) fn mark_truncated(&mut self) {
        self.truncated = true;
    }
}

/// Iterator over received ancillary messages.
#[derive(Debug)]
pub struct AncillaryMessages<'a> {
    yielded: bool,
    recv_fds: &'a [RawFd],
}

impl<'a> Iterator for AncillaryMessages<'a> {
    type Item = AncillaryMessage<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.yielded {
            return None;
        }
        self.yielded = true;
        if self.recv_fds.is_empty() {
            None
        } else {
            Some(AncillaryMessage::ScmRights(ScmRights {
                fds: self.recv_fds,
            }))
        }
    }
}

/// A parsed ancillary message.
#[derive(Debug)]
pub enum AncillaryMessage<'a> {
    /// File descriptors passed via `SCM_RIGHTS`.
    ScmRights(ScmRights<'a>),
}

/// File descriptors received via `SCM_RIGHTS`.
///
/// These are raw fds; the caller must either close them or wrap them in an owned type.
#[derive(Debug)]
pub struct ScmRights<'a> {
    fds: &'a [RawFd],
}

impl Iterator for ScmRights<'_> {
    type Item = RawFd;

    fn next(&mut self) -> Option<Self::Item> {
        self.fds.split_first().map(|(fd, rest)| {
            self.fds = rest;
            *fd
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.fds.len(), Some(self.fds.len()))
    }
}

impl ExactSizeIterator for ScmRights<'_> {}

/// Computes a conservative buffer size for receiving ancillary data containing the given
/// number of file descriptors.
///
/// This is an upper bound (it may over-allocate), but avoids `unsafe` access to libc's
/// `CMSG_*` macros in this crate.
#[must_use]
pub fn ancillary_space_for_fds(fd_count: usize) -> usize {
    if fd_count == 0 {
        0
    } else {
        // Over-estimate by assuming one header per fd. This is fine: callers allocate once.
        let per = nix::sys::socket::cmsg_space::<RawFd>();
        fd_count.saturating_mul(per)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_ancillary_new() {
        init_test("test_ancillary_new");
        let ancillary = SocketAncillary::new(128);

        crate::assert_with_log!(
            ancillary.capacity() == 128,
            "capacity",
            128,
            ancillary.capacity()
        );
        crate::assert_with_log!(ancillary.is_empty(), "is_empty", true, ancillary.is_empty());
        crate::assert_with_log!(
            !ancillary.is_truncated(),
            "truncated",
            false,
            ancillary.is_truncated()
        );
        crate::test_complete!("test_ancillary_new");
    }

    #[test]
    fn test_add_fds() {
        init_test("test_add_fds");
        let mut ancillary = SocketAncillary::new(128);

        // Add some fake fds (we're not actually sending them)
        let fds = [3, 4, 5];
        let added = ancillary.add_fds(&fds);

        crate::assert_with_log!(added, "added", true, added);
        crate::assert_with_log!(
            !ancillary.is_empty(),
            "not empty",
            false,
            ancillary.is_empty()
        );
        crate::test_complete!("test_add_fds");
    }

    #[test]
    fn test_add_fds_too_small_buffer() {
        init_test("test_add_fds_too_small");
        // Capacity only affects receive; send-side queueing is unbounded here.
        let mut ancillary = SocketAncillary::new(4);

        let fds = [3, 4, 5];
        let added = ancillary.add_fds(&fds);

        crate::assert_with_log!(added, "added", true, added);
        crate::assert_with_log!(
            !ancillary.is_empty(),
            "not empty",
            false,
            ancillary.is_empty()
        );
        crate::test_complete!("test_add_fds_too_small");
    }

    #[test]
    fn test_clear() {
        init_test("test_ancillary_clear");
        let mut ancillary = SocketAncillary::new(128);

        ancillary.add_fds(&[3, 4]);
        crate::assert_with_log!(
            !ancillary.is_empty(),
            "not empty",
            false,
            ancillary.is_empty()
        );

        ancillary.clear();
        crate::assert_with_log!(
            ancillary.is_empty(),
            "empty after clear",
            true,
            ancillary.is_empty()
        );
        crate::test_complete!("test_ancillary_clear");
    }

    #[test]
    fn test_ancillary_space_for_fds() {
        init_test("test_ancillary_space_for_fds");

        let space0 = ancillary_space_for_fds(0);
        crate::assert_with_log!(space0 == 0, "space for 0", 0, space0);

        let space1 = ancillary_space_for_fds(1);
        crate::assert_with_log!(space1 > 0, "space for 1 > 0", true, space1 > 0);

        let space3 = ancillary_space_for_fds(3);
        crate::assert_with_log!(space3 > space1, "space for 3 > 1", true, space3 > space1);

        crate::test_complete!("test_ancillary_space_for_fds");
    }
}
