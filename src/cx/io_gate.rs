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
mod tests {
    use super::*;
    use crate::cx::cap;
    use std::cell::{Cell, RefCell};
    use std::marker::PhantomPinned;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::rc::Rc;
    use std::task::Waker;

    type Events = Rc<RefCell<Vec<(&'static str, bool)>>>;

    #[derive(Clone, Copy)]
    enum Behavior {
        Pending,
        Ready,
        Panic,
    }

    // Every probe is !Unpin. The observed gate is the production gate used by
    // filesystem, network and process entry points, not a second mask model.
    struct Probe {
        events: Events,
        behavior: Behavior,
        address: Cell<Option<usize>>,
        panic_on_drop: bool,
        _pin: PhantomPinned,
    }

    impl Probe {
        fn new(events: &Events, behavior: Behavior) -> Self {
            Self {
                events: Rc::clone(events),
                behavior,
                address: Cell::new(None),
                panic_on_drop: false,
                _pin: PhantomPinned,
            }
        }
    }

    impl Future for Probe {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
            let this = self.as_ref().get_ref();
            let address = std::ptr::from_ref(this).addr();
            if let Some(previous) = this.address.replace(Some(address)) {
                assert_eq!(address, previous, "future moved between polls");
            }
            this.events.borrow_mut().push(("poll", require_ambient_io("test.poll").is_ok()));
            match this.behavior {
                Behavior::Pending => Poll::Pending,
                Behavior::Ready => Poll::Ready(()),
                Behavior::Panic => panic!("intentional poll panic"),
            }
        }
    }

    impl Drop for Probe {
        fn drop(&mut self) {
            if let Some(address) = self.address.get() {
                assert_eq!(std::ptr::from_ref(self).addr(), address, "pinned future moved before drop");
            }
            let first_drop = !self.events.borrow().iter().any(|(stage, _)| *stage == "drop");
            self.events.borrow_mut().push(("drop", require_ambient_io("test.drop").is_ok()));
            // A duplicate drop fails the event-count assertion rather than
            // aborting the entire suite with a second panic while unwinding.
            assert!(!(self.panic_on_drop && first_drop), "intentional drop panic");
        }
    }

    #[test]
    fn never_polled_drop_keeps_static_restriction_without_ambient_context() {
        assert!(Cx::current().is_none());
        let mut cx = Cx::for_testing().restrict::<cap::None>();
        // Exercise the static row independently of the carried runtime mask.
        cx.runtime_mask = CapMask::all();
        let events = Events::default();
        drop(cx.with_ambient(Probe::new(&events, Behavior::Pending)));
        assert_eq!(*events.borrow(), [("drop", false)]);
        assert!(Cx::current().is_none());
    }

    #[test]
    fn pending_drop_keeps_authority_and_pin_then_restores_parent() {
        let parent = Cx::for_testing();
        let _parent = Cx::set_current(Some(parent.clone()));
        let depth = Cx::restriction_depth();
        let cx = parent.restrict::<cap::None>();
        let events = Events::default();
        let mut future = Box::pin(cx.with_ambient(Probe::new(&events, Behavior::Pending)));
        let mut task = Context::from_waker(Waker::noop());
        assert!(future.as_mut().poll(&mut task).is_pending());
        assert!(require_ambient_io("parent.after_poll").is_ok());
        assert_eq!(Cx::restriction_depth(), depth);
        assert!(future.as_mut().poll(&mut task).is_pending());
        drop(future);
        assert_eq!(*events.borrow(), [("poll", false), ("poll", false), ("drop", false)]);
        assert!(require_ambient_io("parent.after_drop").is_ok());
        assert_eq!(Cx::restriction_depth(), depth);
    }

    #[test]
    fn completed_future_cleanup_still_uses_its_own_authority() {
        let _parent = Cx::set_current(Some(Cx::for_testing()));
        let cx = Cx::for_testing().restrict::<cap::None>();
        let events = Events::default();
        let mut future = Box::pin(cx.with_ambient(Probe::new(&events, Behavior::Ready)));
        assert!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_ready());
        assert_eq!(*events.borrow(), [("poll", false)]);
        drop(future);
        assert_eq!(*events.borrow(), [("poll", false), ("drop", false)]);
        assert!(require_ambient_io("parent").is_ok());
    }

    #[test]
    fn erased_context_keeps_runtime_restriction_during_drop() {
        let _parent = Cx::set_current(Some(Cx::for_testing()));
        let mut cx = Cx::for_testing();
        cx.runtime_mask = CapMask::none();
        let events = Events::default();
        drop(cx.with_ambient(Probe::new(&events, Behavior::Pending)));
        assert_eq!(*events.borrow(), [("drop", false)]);
        assert!(require_ambient_io("parent").is_ok());
    }

    #[test]
    fn nested_wrappers_restore_each_owners_authority() {
        let parent = Cx::for_testing();
        let _parent = Cx::set_current(Some(parent.clone()));
        let depth = Cx::restriction_depth();
        let cx = parent.restrict::<cap::None>();
        let events = Events::default();
        let inner = cx.with_ambient(Probe::new(&events, Behavior::Pending));
        let mut future = Box::pin(parent.with_ambient(inner));
        assert!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        drop(future);
        assert_eq!(*events.borrow(), [("poll", false), ("drop", false)]);
        assert!(require_ambient_io("parent").is_ok());
        assert_eq!(Cx::restriction_depth(), depth);
    }

    #[test]
    fn explicit_full_context_is_not_replaced_by_the_droppers_restriction() {
        let cx = Cx::for_testing();
        let _parent = cx.restrict::<cap::None>().set_current_restricted();
        let depth = Cx::restriction_depth();
        let events = Events::default();
        drop(cx.with_ambient(Probe::new(&events, Behavior::Pending)));
        assert_eq!(*events.borrow(), [("drop", true)]);
        assert!(require_ambient_io("parent").is_err());
        assert_eq!(Cx::restriction_depth(), depth);
    }

    #[test]
    fn poll_panic_unwinds_future_under_owned_context() {
        let _parent = Cx::set_current(Some(Cx::for_testing()));
        let depth = Cx::restriction_depth();
        let cx = Cx::for_testing().restrict::<cap::None>();
        let events = Events::default();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut future = Box::pin(cx.with_ambient(Probe::new(&events, Behavior::Panic)));
            let _ = future.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        }));
        assert!(result.is_err());
        assert_eq!(*events.borrow(), [("poll", false), ("drop", false)]);
        assert!(require_ambient_io("parent").is_ok());
        assert_eq!(Cx::restriction_depth(), depth);
    }

    #[test]
    fn drop_panic_restores_parent_without_dropping_future_twice() {
        let _parent = Cx::set_current(Some(Cx::for_testing()));
        let depth = Cx::restriction_depth();
        let cx = Cx::for_testing().restrict::<cap::None>();
        let events = Events::default();
        let mut probe = Probe::new(&events, Behavior::Pending);
        probe.panic_on_drop = true;
        let future = Box::pin(cx.with_ambient(probe));
        let result = catch_unwind(AssertUnwindSafe(|| drop(future)));
        assert!(result.is_err());
        assert_eq!(*events.borrow(), [("drop", false)]);
        assert!(require_ambient_io("parent").is_ok());
        assert_eq!(Cx::restriction_depth(), depth);
    }

    #[test]
    fn factory_is_lazy_and_scopes_construction_polling_and_pending_cleanup() {
        let _parent = Cx::set_current(Some(Cx::for_testing()));
        let depth = Cx::restriction_depth();
        let cx = Cx::for_testing().restrict::<cap::None>();
        let events = Events::default();
        let mut future = Box::pin(cx.with_ambient_fn(|| {
            events.borrow_mut().push(("construct", require_ambient_io("test.construct").is_ok()));
            Probe::new(&events, Behavior::Pending)
        }));
        assert!(events.borrow().is_empty(), "factory must not run at construction");
        let mut task = Context::from_waker(Waker::noop());
        assert!(future.as_mut().poll(&mut task).is_pending());
        assert!(future.as_mut().poll(&mut task).is_pending());
        drop(future);
        assert_eq!(*events.borrow(), [
            ("construct", false), ("poll", false), ("poll", false), ("drop", false),
        ]);
        assert!(require_ambient_io("parent").is_ok());
        assert_eq!(Cx::restriction_depth(), depth);
    }

    #[test]
    fn ready_factory_drops_inner_future_once_under_its_context() {
        let _parent = Cx::set_current(Some(Cx::for_testing()));
        let cx = Cx::for_testing().restrict::<cap::None>();
        let events = Events::default();
        let mut future = Box::pin(cx.with_ambient_fn(|| {
            events.borrow_mut().push(("construct", require_ambient_io("test.construct").is_ok()));
            Probe::new(&events, Behavior::Ready)
        }));
        assert!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_ready());
        drop(future);
        assert_eq!(*events.borrow(), [("construct", false), ("poll", false), ("drop", false)]);
        assert!(require_ambient_io("parent").is_ok());
    }

    #[test]
    fn unpolled_factory_drops_captures_without_invoking_factory() {
        let _parent = Cx::set_current(Some(Cx::for_testing()));
        let cx = Cx::for_testing().restrict::<cap::None>();
        let calls = Rc::new(Cell::new(0));
        let called = Rc::clone(&calls);
        let events = Events::default();
        let capture = Probe::new(&events, Behavior::Pending);
        let future = cx.with_ambient_fn(move || {
            called.set(called.get() + 1);
            capture
        });
        drop(future);
        assert_eq!(calls.get(), 0);
        assert_eq!(*events.borrow(), [("drop", false)]);
        assert!(require_ambient_io("parent").is_ok());
    }

    #[test]
    fn factory_panic_cleans_captures_and_restores_the_parent() {
        let _parent = Cx::set_current(Some(Cx::for_testing()));
        let depth = Cx::restriction_depth();
        let cx = Cx::for_testing().restrict::<cap::None>();
        let events = Events::default();
        let capture = Probe::new(&events, Behavior::Pending);
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut future = Box::pin(cx.with_ambient_fn(move || -> std::future::Ready<()> {
                let _capture = capture;
                assert!(require_ambient_io("test.construct").is_err());
                panic!("intentional factory panic");
            }));
            let _ = future.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        }));
        assert!(result.is_err());
        assert_eq!(*events.borrow(), [("drop", false)]);
        assert!(require_ambient_io("parent").is_ok());
        assert_eq!(Cx::restriction_depth(), depth);
    }

    #[test]
    fn owned_factory_future_is_send_static_and_does_not_borrow_receiver() {
        fn assert_send_static<T: Send + 'static>(_: &T) {}
        let future = {
            let cx = Cx::for_testing();
            cx.with_ambient_fn(|| std::future::ready(73_u8))
        };
        assert_send_static(&future);
        assert_eq!(futures_lite::future::block_on(future), 73);
    }

    #[test]
    fn factory_and_output_may_borrow_without_static_bounds() {
        let cx = Cx::for_testing();
        let text = String::from("borrowed adapter state");
        let result = futures_lite::future::block_on(
            cx.with_ambient_fn(|| std::future::ready(text.as_str())),
        );
        assert_eq!(result, text);
    }

    #[test]
    fn factory_uses_explicit_authority_not_the_polling_tasks_restriction() {
        let cx = Cx::for_testing();
        let _parent = cx.restrict::<cap::None>().set_current_restricted();
        let depth = Cx::restriction_depth();
        let result = futures_lite::future::block_on(cx.with_ambient_fn(|| {
            std::future::ready(require_ambient_io("test.construct").is_ok())
        }));
        assert!(result);
        assert!(require_ambient_io("parent").is_err());
        assert_eq!(Cx::restriction_depth(), depth);
    }

    #[test]
    fn returned_outputs_are_owned_by_the_caller_not_the_ambient_wrapper() {
        let _parent = Cx::set_current(Some(Cx::for_testing()));
        let cx = Cx::for_testing().restrict::<cap::None>();
        let events = Events::default();
        let output = futures_lite::future::block_on(cx.with_ambient_fn(|| {
            assert!(require_ambient_io("test.construct").is_err());
            std::future::ready(Probe::new(&events, Behavior::Pending))
        }));
        assert!(events.borrow().is_empty());
        drop(output);
        assert_eq!(*events.borrow(), [("drop", true)]);
    }
}
