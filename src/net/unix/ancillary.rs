#![allow(unsafe_code)]
//! Unix socket ancillary data for file descriptor passing.
//!
//! This module uses unsafe code for interfacing with libc socket control
//! message functions (CMSG_SPACE, CMSG_LEN, CMSG_DATA).
//!
//! This module provides [`SocketAncillary`] for sending and receiving ancillary
//! data (control messages) over Unix domain sockets, including file descriptor passing.
//!
//! # File Descriptor Passing
//!
//! Unix domain sockets support passing file descriptors between processes using
//! the `SCM_RIGHTS` control message. This allows one process to share open files,
//! sockets, or other file descriptors with another process.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::net::unix::{UnixStream, SocketAncillary, AncillaryMessage};
//! use std::os::unix::io::{AsRawFd, FromRawFd};
//! use std::fs::File;
//!
//! async fn send_file_descriptor() -> std::io::Result<()> {
//!     let (tx, rx) = UnixStream::pair()?;
//!
//!     // Open a file and send its descriptor
//!     let file = File::open("/etc/passwd")?;
//!     let fd = file.as_raw_fd();
//!
//!     let mut ancillary = SocketAncillary::new(&mut [0u8; 128]);
//!     ancillary.add_fds(&[fd]);
//!     tx.send_with_ancillary(b"here's a file", &mut ancillary).await?;
//!
//!     // Receive the file descriptor
//!     let mut buf = [0u8; 64];
//!     let mut recv_ancillary = SocketAncillary::new(&mut [0u8; 128]);
//!     let n = rx.recv_with_ancillary(&mut buf, &mut recv_ancillary).await?;
//!
//!     for msg in recv_ancillary.messages() {
//!         if let AncillaryMessage::ScmRights(fds) = msg {
//!             for fd in fds {
//!                 // SAFETY: We received this fd from the sender
//!                 let received_file = unsafe { File::from_raw_fd(fd) };
//!                 // Use the received file...
//!             }
//!         }
//!     }
//!     Ok(())
//! }
//! ```
//!
//! # Safety
//!
//! When receiving file descriptors, the caller is responsible for properly
//! managing their lifetimes. Received file descriptors should typically be
//! wrapped in a type that implements `Drop` (like `File` or `OwnedFd`) to
//! ensure they are closed when no longer needed.

use std::marker::PhantomData;
use std::mem;
use std::os::unix::io::RawFd;
use std::ptr;

/// Buffer for Unix socket ancillary data (control messages).
///
/// This struct wraps a byte buffer used for sending and receiving ancillary
/// data with Unix domain sockets. It handles the complex layout of `cmsghdr`
/// structures required by the kernel.
///
/// # Creating a Buffer
///
/// The buffer size depends on what you want to send/receive:
/// - For file descriptors: `CMSG_SPACE(num_fds * size_of::<RawFd>())`
/// - A good default for a few file descriptors is 128 bytes
///
/// # Example
///
/// ```ignore
/// let mut buffer = [0u8; 128];
/// let mut ancillary = SocketAncillary::new(&mut buffer);
/// ancillary.add_fds(&[fd1, fd2]);
/// ```
#[derive(Debug)]
pub struct SocketAncillary<'a> {
    /// The underlying buffer for control messages.
    buffer: &'a mut [u8],
    /// Current length of valid data in the buffer.
    length: usize,
    /// Whether truncation occurred during receive.
    truncated: bool,
}

impl<'a> SocketAncillary<'a> {
    /// Creates a new `SocketAncillary` with the given buffer.
    ///
    /// The buffer should be large enough to hold the control messages you
    /// want to send or receive. For file descriptors, use at least
    /// `CMSG_SPACE(num_fds * size_of::<RawFd>())` bytes.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut buf = [0u8; 128];
    /// let ancillary = SocketAncillary::new(&mut buf);
    /// ```
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            length: 0,
            truncated: false,
        }
    }

    /// Returns the capacity of the buffer in bytes.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.buffer.len()
    }

    /// Returns the current length of valid ancillary data.
    #[must_use]
    pub fn len(&self) -> usize {
        self.length
    }

    /// Returns `true` if there is no ancillary data.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Returns `true` if the ancillary data was truncated during receive.
    ///
    /// Truncation occurs when the received control messages exceed the
    /// buffer capacity. When this happens, some file descriptors may have
    /// been lost (and leaked).
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Clears the ancillary data buffer.
    pub fn clear(&mut self) {
        self.length = 0;
        self.truncated = false;
    }

    /// Adds file descriptors to be sent as `SCM_RIGHTS`.
    ///
    /// Returns `true` if the file descriptors were added successfully,
    /// or `false` if there wasn't enough space in the buffer.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let fd = file.as_raw_fd();
    /// if !ancillary.add_fds(&[fd]) {
    ///     panic!("Buffer too small for file descriptors");
    /// }
    /// ```
    pub fn add_fds(&mut self, fds: &[RawFd]) -> bool {
        if fds.is_empty() {
            return true;
        }

        let fd_size = fds.len() * mem::size_of::<RawFd>();
        let cmsg_space = unsafe { libc::CMSG_SPACE(fd_size as u32) } as usize;

        if self.length + cmsg_space > self.buffer.len() {
            return false;
        }

        // SAFETY: We've verified there's enough space in the buffer.
        unsafe {
            let cmsg_ptr = self.buffer.as_mut_ptr().add(self.length) as *mut libc::cmsghdr;

            (*cmsg_ptr).cmsg_len = libc::CMSG_LEN(fd_size as u32) as _;
            (*cmsg_ptr).cmsg_level = libc::SOL_SOCKET;
            (*cmsg_ptr).cmsg_type = libc::SCM_RIGHTS;

            let data_ptr = libc::CMSG_DATA(cmsg_ptr) as *mut RawFd;
            ptr::copy_nonoverlapping(fds.as_ptr(), data_ptr, fds.len());
        }

        self.length += cmsg_space;
        true
    }

    /// Returns an iterator over the ancillary messages.
    ///
    /// # Example
    ///
    /// ```ignore
    /// for msg in ancillary.messages() {
    ///     match msg {
    ///         AncillaryMessage::ScmRights(fds) => {
    ///             for fd in fds {
    ///                 println!("Received fd: {}", fd);
    ///             }
    ///         }
    ///         AncillaryMessage::Unknown { level, ty } => {
    ///             println!("Unknown message: level={}, type={}", level, ty);
    ///         }
    ///     }
    /// }
    /// ```
    pub fn messages(&self) -> AncillaryMessages<'_> {
        AncillaryMessages {
            buffer: &self.buffer[..self.length],
            current: 0,
            _marker: PhantomData,
        }
    }

    /// Returns a pointer to the buffer for use with sendmsg/recvmsg.
    ///
    /// # Safety
    ///
    /// The caller must ensure the buffer remains valid for the duration of
    /// the system call.
    pub(crate) fn as_mut_ptr(&mut self) -> *mut u8 {
        self.buffer.as_mut_ptr()
    }

    /// Sets the length after a successful recvmsg.
    ///
    /// # Safety
    ///
    /// The caller must ensure `len` bytes of valid control message data
    /// have been written to the buffer.
    pub(crate) unsafe fn set_len(&mut self, len: usize, truncated: bool) {
        self.length = len.min(self.buffer.len());
        self.truncated = truncated;
    }
}

/// Iterator over ancillary messages.
#[derive(Debug)]
pub struct AncillaryMessages<'a> {
    buffer: &'a [u8],
    current: usize,
    _marker: PhantomData<&'a ()>,
}

impl<'a> Iterator for AncillaryMessages<'a> {
    type Item = AncillaryMessage<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.buffer.len() {
            return None;
        }

        // SAFETY: We're iterating through a valid control message buffer
        // that was filled by recvmsg.
        unsafe {
            let cmsg_ptr = self.buffer.as_ptr().add(self.current) as *const libc::cmsghdr;

            // Check if we have at least a header
            if self.current + mem::size_of::<libc::cmsghdr>() > self.buffer.len() {
                return None;
            }

            let cmsg_len = (*cmsg_ptr).cmsg_len as usize;
            if cmsg_len < mem::size_of::<libc::cmsghdr>() {
                return None;
            }

            // Advance to next message
            let cmsg_space =
                libc::CMSG_SPACE((cmsg_len - mem::size_of::<libc::cmsghdr>()) as u32) as usize;
            self.current += cmsg_space.max(mem::size_of::<libc::cmsghdr>());

            let level = (*cmsg_ptr).cmsg_level;
            let ty = (*cmsg_ptr).cmsg_type;
            let data_ptr = libc::CMSG_DATA(cmsg_ptr);
            let data_len = cmsg_len - mem::size_of::<libc::cmsghdr>();

            if level == libc::SOL_SOCKET && ty == libc::SCM_RIGHTS {
                let fd_count = data_len / mem::size_of::<RawFd>();
                let fds = std::slice::from_raw_parts(data_ptr as *const RawFd, fd_count);
                Some(AncillaryMessage::ScmRights(ScmRights { fds }))
            } else {
                Some(AncillaryMessage::Unknown { level, ty })
            }
        }
    }
}

/// A parsed ancillary message.
#[derive(Debug)]
pub enum AncillaryMessage<'a> {
    /// File descriptors passed via `SCM_RIGHTS`.
    ScmRights(ScmRights<'a>),
    /// An unknown or unsupported control message.
    Unknown {
        /// The protocol level (e.g., `SOL_SOCKET`).
        level: i32,
        /// The message type.
        ty: i32,
    },
}

/// File descriptors received via `SCM_RIGHTS`.
///
/// # Safety
///
/// The file descriptors returned by this iterator are raw and ownership
/// is transferred to the receiver. The caller must ensure they are either:
/// - Wrapped in an owned type (like `OwnedFd` or `File`) to be closed on drop
/// - Explicitly closed with `libc::close()`
///
/// Failing to do so will leak file descriptors.
#[derive(Debug)]
pub struct ScmRights<'a> {
    fds: &'a [RawFd],
}

impl<'a> Iterator for ScmRights<'a> {
    type Item = RawFd;

    fn next(&mut self) -> Option<Self::Item> {
        if self.fds.is_empty() {
            None
        } else {
            let fd = self.fds[0];
            self.fds = &self.fds[1..];
            Some(fd)
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.fds.len(), Some(self.fds.len()))
    }
}

impl ExactSizeIterator for ScmRights<'_> {}

/// Computes the space required for ancillary data containing the given
/// number of file descriptors.
///
/// # Example
///
/// ```ignore
/// let space = ancillary_space_for_fds(3);
/// let mut buffer = vec![0u8; space];
/// let mut ancillary = SocketAncillary::new(&mut buffer);
/// ```
#[must_use]
pub fn ancillary_space_for_fds(fd_count: usize) -> usize {
    if fd_count == 0 {
        0
    } else {
        let fd_size = fd_count * mem::size_of::<RawFd>();
        unsafe { libc::CMSG_SPACE(fd_size as u32) as usize }
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
        let mut buffer = [0u8; 128];
        let ancillary = SocketAncillary::new(&mut buffer);

        crate::assert_with_log!(
            ancillary.capacity() == 128,
            "capacity",
            128,
            ancillary.capacity()
        );
        crate::assert_with_log!(ancillary.len() == 0, "len", 0, ancillary.len());
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
        let mut buffer = [0u8; 128];
        let mut ancillary = SocketAncillary::new(&mut buffer);

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
        // Very small buffer
        let mut buffer = [0u8; 4];
        let mut ancillary = SocketAncillary::new(&mut buffer);

        let fds = [3, 4, 5];
        let added = ancillary.add_fds(&fds);

        crate::assert_with_log!(!added, "not added", false, added);
        crate::assert_with_log!(
            ancillary.is_empty(),
            "still empty",
            true,
            ancillary.is_empty()
        );
        crate::test_complete!("test_add_fds_too_small");
    }

    #[test]
    fn test_clear() {
        init_test("test_ancillary_clear");
        let mut buffer = [0u8; 128];
        let mut ancillary = SocketAncillary::new(&mut buffer);

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
