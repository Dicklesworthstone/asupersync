//! The ambient I/O gate (br-asupersync-issue65-criticisms-kpmoy5.5.3).
//!
//! Runtime-managed I/O entry points that take no [`Cx`] (`TcpStream::connect`,
//! `fs::read`, `process::Command::spawn` and the like) consult the ambient
//! context. When the calling task's context lacks the IO capability, for
//! example after [`Cx::push_restriction`] or in an AppSpec work unit that
//! requires neither io nor net, they refuse with [`IoCapabilityDenied`]
//! (`[ASUP-E009]`).
//! Code with no current context (plain threads, code outside the runtime) and
//! code whose context carries IO are unaffected.

use crate::cx::Cx;
use crate::cx::cap::CapMask;
use std::io;

/// An ambient I/O entry point refused because the calling task's [`Cx`]
/// lacks the IO capability (`[ASUP-E009]`).
///
/// It arrives as the inner error of an [`io::Error`] of kind
/// [`io::ErrorKind::PermissionDenied`]:
///
/// ```
/// use asupersync::cx::IoCapabilityDenied;
///
/// fn denied(error: &std::io::Error) -> Option<&IoCapabilityDenied> {
///     error.get_ref()?.downcast_ref::<IoCapabilityDenied>()
/// }
/// # let _ = denied;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoCapabilityDenied {
    operation: &'static str,
}

impl IoCapabilityDenied {
    /// The entry point that refused, for example `"net::TcpStream::connect"`.
    #[must_use]
    pub const fn operation(&self) -> &'static str {
        self.operation
    }
}

impl std::fmt::Display for IoCapabilityDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[ASUP-E009] {} refused: the calling task's Cx lacks the IO capability",
            self.operation
        )
    }
}

impl std::error::Error for IoCapabilityDenied {}

/// Refuses `operation` when the ambient context lacks the IO capability.
///
/// One thread-local borrow and a mask test; it allocates only to build the
/// refusal.
#[inline]
pub fn require_ambient_io(operation: &'static str) -> io::Result<()> {
    let permitted = Cx::with_current(|cx| cx.runtime_mask.has(CapMask::IO)).unwrap_or(true);
    if permitted {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            IoCapabilityDenied { operation },
        ))
    }
}

/// [`crate::runtime::spawn_blocking_io`] for the path-based filesystem entry
/// points (`fs::read`, `fs::create_dir_all`, `fs::read_dir`, ...): the gate
/// runs first, on the calling task's thread, where its context is current.
pub async fn spawn_blocking_io<F, T>(f: F) -> io::Result<T>
where
    F: FnOnce() -> io::Result<T> + Send + 'static,
    T: Send + 'static,
{
    require_ambient_io("fs")?;
    crate::runtime::spawn_blocking_io(f).await
}
