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
use crate::cx::cap::{CapMask, CapSetRuntimeMask};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

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

impl<Caps: CapSetRuntimeMask> Cx<Caps> {
    /// Runs `future` with this context as the ambient context during each of
    /// its polls, so the I/O entry points that take no `Cx` inside it
    /// (`TcpStream::connect`, `fs::read`, `process::Command::spawn`, ...) are
    /// checked against this context instead of the calling task's.
    ///
    /// This is the explicit form of those entry points: the authority they
    /// use is the context passed here, exactly as narrow as its capability
    /// type and its runtime mask (see [`Cx::set_current_restricted`]). A
    /// context without the IO capability makes them refuse with
    /// [`IoCapabilityDenied`].
    ///
    /// ```ignore
    /// let stream = cx.with_ambient(TcpStream::connect(addr)).await?;
    /// let bytes = cx.with_ambient(asupersync::fs::read(path)).await?;
    /// ```
    pub fn with_ambient<F: Future>(&self, future: F) -> WithAmbient<Caps, F> {
        WithAmbient {
            cx: self.clone(),
            future,
        }
    }
}

/// Future returned by [`Cx::with_ambient`].
#[pin_project::pin_project]
#[must_use = "futures do nothing unless polled"]
pub struct WithAmbient<Caps, F> {
    cx: Cx<Caps>,
    #[pin]
    future: F,
}

impl<Caps, F> std::fmt::Debug for WithAmbient<Caps, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WithAmbient").finish_non_exhaustive()
    }
}

impl<Caps: CapSetRuntimeMask, F: Future> Future for WithAmbient<Caps, F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, task_cx: &mut Context<'_>) -> Poll<F::Output> {
        let this = self.project();
        let _ambient = this.cx.clone().set_current_restricted();
        this.future.poll(task_cx)
    }
}
