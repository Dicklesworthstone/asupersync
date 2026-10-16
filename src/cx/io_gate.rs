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
/// Its only callers are in `fs`, which wasm32 builds leave out.
#[cfg(not(target_arch = "wasm32"))]
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
    /// The same context is installed while destroying the inner future,
    /// including cancellation by drop before its first poll and panic unwinding.
    /// The previous ambient context is restored after both polling and cleanup.
    /// This does not scope work already performed while constructing `future`,
    /// nor the later destruction of an output returned to the caller. Use
    /// [`Self::with_ambient_fn`] to include synchronous future construction.
    ///
    /// ```ignore
    /// let stream = cx.with_ambient(TcpStream::connect(addr)).await?;
    /// let bytes = cx.with_ambient(asupersync::fs::read(path)).await?;
    /// ```
    pub fn with_ambient<F: Future>(&self, future: F) -> WithAmbient<Caps, F> {
        // Preserve the type-level restriction in the owned runtime mask too:
        // pinned destruction must install it without adding a Caps bound to
        // WithAmbient's existing public type.
        let mut cx = self.clone();
        cx.runtime_mask = Caps::MASK.intersect(cx.runtime_mask);
        WithAmbient {
            cx,
            future: Some(future),
        }
    }

    /// Construct, poll and destroy a future under this explicit context.
    ///
    /// Unlike passing an already constructed future to [`Self::with_ambient`],
    /// this runs the synchronous body of `make` under the supplied capability
    /// mask too. Use it for adapters whose constructors consult the ambient
    /// context or perform effects before returning their future.
    ///
    /// The factory is invoked once, on the first poll, not when this method is
    /// called. Dropping the returned future before polling does not invoke the
    /// factory; its captures are still destroyed under the supplied context.
    /// Factory panic cleanup, subsequent polls, and destruction of the produced
    /// future use that same context. Every poll/drop restores the previous
    /// ambient context; no thread-local guard is held across an await.
    ///
    /// Constructing the closure and its captures happens at the call site,
    /// outside this boundary. Output values returned to the caller belong to
    /// the caller. This does not spawn a task, install a cancellation checkpoint,
    /// or supply asynchronous cleanup for an operation abandoned by drop.
    /// Factories and futures may borrow; owned ones do not borrow this `Cx`.
    pub fn with_ambient_fn<Make, F>(
        &self,
        make: Make,
    ) -> WithAmbient<Caps, impl Future<Output = F::Output> + use<Caps, Make, F>>
    where
        Make: FnOnce() -> F,
        F: Future,
    {
        self.with_ambient(async move { make().await })
    }
}

/// Future returned by [`Cx::with_ambient`] and [`Cx::with_ambient_fn`].
#[pin_project::pin_project(PinnedDrop)]
#[must_use = "futures do nothing unless polled"]
pub struct WithAmbient<Caps, F> {
    cx: Cx<Caps>,
    #[pin]
    future: Option<F>,
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
        this.future
            .as_pin_mut()
            .expect("WithAmbient future missing before drop")
            .poll(task_cx)
    }
}

#[pin_project::pinned_drop]
impl<Caps, F> PinnedDrop for WithAmbient<Caps, F> {
    fn drop(self: Pin<&mut Self>) {
        let mut this = self.project();
        // with_ambient already intersected the static capability row into this
        // mask, so erasing the marker cannot restore authority during cleanup.
        let _ambient = this.cx.retype::<crate::cx::cap::All>().set_current_restricted();
        // Pin::set drops F in place before replacing it. Clearing the option
        // here keeps implicit field destruction from running user cleanup after
        // the ambient guard has restored the caller's context.
        this.future.set(None);
    }
}

#[cfg(test)]
#[path = "io_gate_inline_tests.rs"]
mod tests;
