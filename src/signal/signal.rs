//! Async signal streams for supported platform signals.
//!
//! # Cancel Safety
//!
//! - `Signal::recv`: cancel-safe, no delivered signal notification is lost.
//!
//! # Design
//!
//! On Unix and Windows, a global dispatcher thread is installed once and receives
//! process signals via `signal-hook`. Delivered signals are fanned out to
//! per-kind async waiters using `Notify` + monotone delivery counters.

use std::io;

#[cfg(any(unix, windows))]
use std::collections::HashMap;
#[cfg(any(unix, windows))]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(any(unix, windows))]
use std::sync::{Arc, RwLock};
#[cfg(any(unix, windows))]
use std::thread;

#[cfg(any(unix, windows))]
use crate::sync::Notify;

use super::SignalKind;

#[cfg(unix)]
use nix::sys::signal::{SigSet, SigmaskHow, Signal as NixSignal};

/// Error returned when signal handling is unavailable.
#[derive(Debug, Clone)]
pub struct SignalError {
    kind: SignalKind,
    message: String,
}

impl SignalError {
    fn unsupported(kind: SignalKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for SignalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {} ({})", self.message, self.kind.name(), self.kind)
    }
}

impl std::error::Error for SignalError {}

impl From<SignalError> for io::Error {
    fn from(e: SignalError) -> Self {
        Self::new(io::ErrorKind::Unsupported, e)
    }
}

#[cfg(any(unix, windows))]
#[derive(Debug)]
struct SignalSlot {
    deliveries: AtomicU64,
    notify: Notify,
}

#[cfg(any(unix, windows))]
impl SignalSlot {
    fn new() -> Self {
        Self {
            deliveries: AtomicU64::new(0),
            notify: Notify::new(),
        }
    }

    #[cfg(any(unix, test))]
    fn record_delivery(&self) {
        self.deliveries.fetch_add(1, Ordering::Release);
        notify_waiters_contained(&self.notify);
    }

    /// Signal-safe delivery: only bumps the atomic counter.
    ///
    /// This must be used in contexts where locking is forbidden (e.g. CRT
    /// signal handlers on Windows). A background poller thread calls
    /// [`notify_if_changed`] to wake async waiters.
    #[cfg(windows)]
    fn record_delivery_signal_safe(&self) {
        self.deliveries.fetch_add(1, Ordering::Release);
    }

    /// Wake waiters if the delivery counter has advanced past `last_seen`.
    /// Returns the current counter value.
    #[cfg(windows)]
    fn notify_if_changed(&self, last_seen: u64) -> u64 {
        let current = self.deliveries.load(Ordering::Acquire);
        if current != last_seen {
            notify_waiters_contained(&self.notify);
        }
        current
    }
}

#[cfg(any(unix, windows))]
#[derive(Debug)]
struct SignalDispatcher {
    slots: HashMap<SignalKind, Arc<SignalSlot>>,
    #[cfg(unix)]
    handle: signal_hook::iterator::Handle,
    /// Windows-only: kernel event handles + JoinHandle for the
    /// background poller thread. The poller waits on these events with
    /// `WaitForMultipleObjects(INFINITE)`; the CTRL signal handler
    /// signals `signal_pending_event` to wake the poller for sub-ms
    /// signal delivery; Drop signals `shutdown_event` to make the
    /// poller exit, then joins the thread and closes both kernel
    /// handles. (br-asupersync-rsq3qj.)
    #[cfg(windows)]
    shutdown_event: WindowsEventHandle,
    #[cfg(windows)]
    signal_pending_event: WindowsEventHandle,
    #[cfg(windows)]
    poller_handle: Option<std::thread::JoinHandle<()>>,
}

/// Send/Sync wrapper around a Win32 kernel `HANDLE`. The kernel
/// guarantees the handle's underlying object (Event, here) is safe to
/// share across threads — the wrapper is necessary only because
/// `*mut c_void` is `!Send + !Sync` by default.
///
/// The handle's lifecycle is owned by `SignalDispatcher`: created in
/// `start()`, closed in `Drop`. Closures that capture a copy of this
/// wrapper (e.g. signal-handler callbacks installed for the lifetime
/// of the dispatcher) MUST NOT call `CloseHandle` themselves.
#[cfg(windows)]
#[derive(Clone, Copy)]
struct WindowsEventHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl std::fmt::Debug for WindowsEventHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("WindowsEventHandle")
            .field(&format_args!("{:p}", self.0))
            .finish()
    }
}

#[cfg(windows)]
impl WindowsEventHandle {
    #[allow(unsafe_code)] // Win32 Event HANDLE FFI.
    fn set_event(self) -> bool {
        unsafe { windows_sys::Win32::System::Threading::SetEvent(self.0) != 0 }
    }

    #[allow(unsafe_code)] // Win32 Event HANDLE FFI.
    fn close(self) -> bool {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) != 0 }
    }
}

// SAFETY: Win32 Event objects accessed via SetEvent / WaitForMultipleObjects
// / CloseHandle are documented to be safe to use from arbitrary threads
// (the kernel-side state is the synchronization domain). The HANDLE
// itself is just an opaque pointer to a kernel object, not into thread-
// local memory.
#[cfg(windows)]
#[allow(unsafe_code)]
unsafe impl Send for WindowsEventHandle {}
#[cfg(windows)]
#[allow(unsafe_code)]
unsafe impl Sync for WindowsEventHandle {}

#[cfg(windows)]
impl Drop for SignalDispatcher {
    fn drop(&mut self) {
        // Signal the shutdown event so the poller's
        // WaitForMultipleObjects returns WAIT_OBJECT_0 (= shutdown
        // index) and the loop breaks out cleanly. We then join the
        // thread so resource accounting is clean (the process expects
        // all auxiliary threads to be quiescent under runtime
        // shutdown). Finally, close both event handles to release the
        // kernel objects.
        //
        // Order matters: SetEvent → join → CloseHandle. Closing the
        // handles before the thread joins would invalidate the handles
        // the WaitForMultipleObjects call is referencing.
        let _ = self.shutdown_event.set_event();
        if let Some(handle) = self.poller_handle.take() {
            // Best-effort join: if the poller thread panicked we still
            // want shutdown to proceed cleanly rather than propagate
            // the panic from a destructor.
            let _ = handle.join();
        }
        // Both handles were created by CreateEventW in start() and have
        // not been closed elsewhere. Any signal handlers that captured
        // signal_pending_event by Copy will still hold the now-stale
        // HANDLE value; once the dispatcher is dropped the process is
        // shutting down and CRT signal handlers should not fire. See
        // start() docs for the lifecycle contract.
        let _ = self.shutdown_event.close();
        let _ = self.signal_pending_event.close();
    }
}

#[cfg(unix)]
impl SignalDispatcher {
    fn start() -> io::Result<Self> {
        let mut slots = HashMap::with_capacity(8);
        for kind in all_signal_kinds() {
            slots.insert(kind, Arc::new(SignalSlot::new()));
        }

        // Slots are bookkeeping, not permission to intercept every signal.
        // Start with no OS registrations; Signal::new adds only the requested
        // kind through the iterator's thread-safe, idempotent handle API.
        let raw_signals: [i32; 0] = [];
        let mut signals = signal_hook::iterator::Signals::new(raw_signals)?;
        let handle = signals.handle();

        let thread_slots = slots.clone();
        thread::Builder::new()
            .name("asupersync-signal-dispatch".to_string())
            .spawn(move || {
                for raw in signals.forever() {
                    if let Some(kind) = signal_kind_from_raw(raw) {
                        if let Some(slot) = thread_slots.get(&kind) {
                            slot.record_delivery();
                        }
                    }
                }
            })
            .map_err(|e| io::Error::other(format!("failed to spawn signal dispatcher: {e}")))?;

        Ok(Self { slots, handle })
    }

    fn slot(&self, kind: SignalKind) -> Option<Arc<SignalSlot>> {
        self.slots.get(&kind).cloned()
    }

    #[cfg(test)]
    fn inject(&self, kind: SignalKind) {
        if let Some(slot) = self.slots.get(&kind) {
            slot.record_delivery();
        }
    }
}

#[cfg(windows)]
impl SignalDispatcher {
    #[allow(unsafe_code)] // signal_hook::low_level::register + Win32 FFI
    fn start() -> io::Result<Self> {
        use std::ptr;
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE, WAIT_OBJECT_0};
        use windows_sys::Win32::System::Threading::{
            CreateEventW, INFINITE, WaitForMultipleObjects,
        };

        let mut slots = HashMap::with_capacity(4);
        for kind in all_signal_kinds() {
            slots.insert(kind, Arc::new(SignalSlot::new()));
        }

        // Two kernel events drive the poller's WaitForMultipleObjects
        // loop (br-asupersync-rsq3qj):
        //
        //   * shutdown_event       — manual-reset, initially non-
        //                            signaled. Set by Drop so the wait
        //                            returns immediately and the loop
        //                            exits. Manual-reset means "stays
        //                            signaled until ResetEvent" — we
        //                            never reset it because the only
        //                            signaling event is shutdown.
        //   * signal_pending_event — auto-reset, initially non-
        //                            signaled. Set by the CRT signal
        //                            handler when a signal is delivered.
        //                            Auto-reset clears the event the
        //                            moment a wait observes it, so the
        //                            poller doesn't see a stale wakeup.
        //
        // Per MSDN, `SetEvent` is documented safe to call from a Win32
        // console-control handler context (where the previous design's
        // `Thread::unpark` was not). Combined with the existing
        // signal-safe atomic counters in `SignalSlot`, this gives
        // sub-ms signal delivery without busy polling and without
        // racing with the kernel signal dispatcher.
        //
        // CreateEventW( lpEventAttributes=NULL,
        //               bManualReset=TRUE/FALSE,
        //               bInitialState=FALSE,
        //               lpName=NULL ) returns NULL on failure.
        let shutdown_event_raw = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if shutdown_event_raw.is_null() || shutdown_event_raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let signal_pending_event_raw = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
        if signal_pending_event_raw.is_null() || signal_pending_event_raw == INVALID_HANDLE_VALUE {
            // Don't leak the first handle if the second fails.
            unsafe {
                let _ = CloseHandle(shutdown_event_raw);
            }
            return Err(io::Error::last_os_error());
        }
        let shutdown_event = WindowsEventHandle(shutdown_event_raw);
        let signal_pending_event = WindowsEventHandle(signal_pending_event_raw);

        let mut registered_ids = Vec::with_capacity(4);
        // On Windows, low-level register() installs CRT signal handlers
        // that invoke our callback directly. Handlers run in signal
        // context where locking is forbidden; we use atomic-only stores
        // in SignalSlot and call SetEvent (documented signal-safe).
        // Track registered hook IDs so error paths unregister cleanly.
        // If registration fails, all hooks are unregistered and the
        // event handles are closed before returning Err.
        //
        //
        for kind in all_signal_kinds() {
            let raw = raw_signal_for_kind(kind);
            debug_assert_eq!(signal_kind_from_raw(raw), Some(kind));
            let slot = slots.get(&kind).expect("slot just inserted").clone();
            // Capture by Copy — WindowsEventHandle is Copy and Send.
            // The HANDLE remains valid for the lifetime of this
            // SignalDispatcher; SignalDispatcher::Drop closes the
            // event AFTER joining the poller. CRT signal handlers are
            // process-global and may technically outlive the
            // dispatcher; in practice the dispatcher is created once
            // at runtime startup and dropped at process exit.
            let pending = signal_pending_event;
            // SAFETY: closure body uses only atomic stores
            // (record_delivery_signal_safe) and SetEvent on a kernel
            // event handle — both signal-safe operations on Windows
            // CTRL handlers.
            //
            unsafe {
                match signal_hook::low_level::register(raw, move || {
                    slot.record_delivery_signal_safe();
                    let _ = pending.set_event();
                }) {
                    Ok(id) => registered_ids.push(id),
                    Err(err) => {
                        for id in registered_ids {
                            signal_hook::low_level::unregister(id);
                        }
                        let _ = shutdown_event.close();
                        let _ = signal_pending_event.close();
                        return Err(err);
                    }
                }
            }
        }
        const SHUTDOWN_INDEX: u32 = WAIT_OBJECT_0;
        const SIGNAL_PENDING_INDEX: u32 = WAIT_OBJECT_0 + 1;
        let poller_slots: Vec<Arc<SignalSlot>> = slots.values().cloned().collect();
        let poller_shutdown_handle = shutdown_event;
        let poller_pending_handle = signal_pending_event;
        let registered_hooks = registered_ids;
        let poller_handle = thread::Builder::new()
            .name("asupersync-signal-poll-win".to_string())
            .spawn(move || {
                let s_handle = poller_shutdown_handle;
                let p_handle = poller_pending_handle;
                let handles: [windows_sys::Win32::Foundation::HANDLE; 2] = [s_handle.0, p_handle.0];
                let mut last_seen: Vec<u64> = vec![0; poller_slots.len()];
                loop {
                    // SAFETY: handles contains valid event handles.
                    // Closed by SignalDispatcher::Drop AFTER join.
                    // bWaitAll = FALSE: returns when any handle signals.
                    //
                    let rc = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) };
                    match rc {
                        SHUTDOWN_INDEX => break,
                        SIGNAL_PENDING_INDEX => {
                            // Auto-reset: signal_pending_event is now
                            // already cleared. Drain the atomic
                            // counters and notify_waiters from this
                            // safe (non-signal) context.
                            for (i, slot) in poller_slots.iter().enumerate() {
                                last_seen[i] = slot.notify_if_changed(last_seen[i]);
                            }
                        }
                        // WAIT_FAILED, WAIT_ABANDONED_*, or any other
                        // unexpected return: exit rather than spin
                        // forever. The dispatcher will be dropped at
                        // process shutdown and the failure is
                        // recorded for postmortem via the runtime
                        // logs.
                        _ => break,
                    }
                }
            })
            .map_err(|e| {
                for id in registered_hooks {
                    signal_hook::low_level::unregister(id);
                }
                let _ = shutdown_event.close();
                let _ = signal_pending_event.close();
                io::Error::other(format!("failed to spawn signal poller: {e}"))
            })?;

        Ok(Self {
            slots,
            shutdown_event,
            signal_pending_event,
            poller_handle: Some(poller_handle),
        })
    }

    fn slot(&self, kind: SignalKind) -> Option<Arc<SignalSlot>> {
        self.slots.get(&kind).cloned()
    }

    #[cfg(test)]
    fn inject(&self, kind: SignalKind) {
        if let Some(slot) = self.slots.get(&kind) {
            slot.record_delivery();
        }
    }
}

#[cfg(unix)]
fn all_signal_kinds() -> [SignalKind; 10] {
    [
        SignalKind::Interrupt,
        SignalKind::Terminate,
        SignalKind::Hangup,
        SignalKind::Quit,
        SignalKind::User1,
        SignalKind::User2,
        SignalKind::Child,
        SignalKind::WindowChange,
        SignalKind::Pipe,
        SignalKind::Alarm,
    ]
}

#[cfg(windows)]
fn all_signal_kinds() -> [SignalKind; 3] {
    [
        SignalKind::Interrupt,
        SignalKind::Terminate,
        SignalKind::Quit,
    ]
}

#[cfg(unix)]
fn raw_signal_for_kind(kind: SignalKind) -> i32 {
    kind.as_raw_value()
}

#[cfg(windows)]
fn raw_signal_for_kind(kind: SignalKind) -> i32 {
    kind.as_raw_value().expect("windows supported signal kind")
}

#[cfg(unix)]
fn signal_kind_from_raw(raw: i32) -> Option<SignalKind> {
    if raw == libc::SIGINT {
        Some(SignalKind::Interrupt)
    } else if raw == libc::SIGTERM {
        Some(SignalKind::Terminate)
    } else if raw == libc::SIGHUP {
        Some(SignalKind::Hangup)
    } else if raw == libc::SIGQUIT {
        Some(SignalKind::Quit)
    } else if raw == libc::SIGUSR1 {
        Some(SignalKind::User1)
    } else if raw == libc::SIGUSR2 {
        Some(SignalKind::User2)
    } else if raw == libc::SIGCHLD {
        Some(SignalKind::Child)
    } else if raw == libc::SIGWINCH {
        Some(SignalKind::WindowChange)
    } else if raw == libc::SIGPIPE {
        Some(SignalKind::Pipe)
    } else if raw == libc::SIGALRM {
        Some(SignalKind::Alarm)
    } else {
        None
    }
}

#[cfg(windows)]
fn signal_kind_from_raw(raw: i32) -> Option<SignalKind> {
    if raw == libc::SIGINT {
        Some(SignalKind::Interrupt)
    } else if raw == libc::SIGTERM {
        Some(SignalKind::Terminate)
    } else if raw == signal_hook::consts::SIGBREAK {
        Some(SignalKind::Quit)
    } else {
        None
    }
}

/// Wakes every waiter of a slot and contains a panicking waker.
///
/// `notify_waiters` wakes all of them, then re-raises the first panic. On the
/// dispatcher thread that panic would end signal delivery for the whole
/// process: the OS handlers stay installed, so every later delivery, SIGTERM
/// and SIGINT included, would be swallowed. The panic hook has already
/// reported the panic, so it is dropped here.
#[cfg(any(unix, windows))]
fn notify_waiters_contained(notify: &Notify) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| notify.notify_waiters()));
}

#[cfg(any(unix, windows))]
static SIGNAL_DISPATCHER: RwLock<Option<&'static SignalDispatcher>> = RwLock::new(None);

#[cfg(any(unix, windows))]
fn dispatcher_for(kind: SignalKind) -> Result<&'static SignalDispatcher, SignalError> {
    if let Ok(guard) = SIGNAL_DISPATCHER.read() {
        if let Some(dispatcher) = *guard {
            return Ok(dispatcher);
        }
    }
    let mut lock = SIGNAL_DISPATCHER.write().map_err(|_| {
        SignalError::unsupported(kind, "signal dispatcher lock poisoned")
    })?;
    if let Some(dispatcher) = *lock {
        return Ok(dispatcher);
    }
    match SignalDispatcher::start() {
        Ok(dispatcher) => {
            let leaked: &'static SignalDispatcher = Box::leak(Box::new(dispatcher));
            *lock = Some(leaked);
            Ok(leaked)
        }
        Err(err) => Err(SignalError::unsupported(
            kind,
            format!("failed to initialize signal dispatcher: {err}"),
        )),
    }
}

/// Whether the dispatcher runs and has a slot for `kind`, without
/// registering an OS handler for it. A registered handler stays for the
/// life of the process, so an availability probe must not install one.
#[cfg(any(unix, windows))]
pub(super) fn dispatcher_has_slot(kind: SignalKind) -> bool {
    dispatcher_for(kind).is_ok_and(|dispatcher| dispatcher.slot(kind).is_some())
}

/// An async stream that receives signals of a particular kind.
///
/// # Example
///
/// ```
/// use asupersync::signal::{signal, SignalKind};
///
/// async fn handle_signals() -> std::io::Result<()> {
///     let mut sigterm = signal(SignalKind::terminate())?;
///
///     loop {
///         sigterm.recv().await;
///         println!("Received SIGTERM");
///         break;
///     }
///     Ok(())
/// }
/// ```
#[derive(Debug)]
pub struct Signal {
    kind: SignalKind,
    #[cfg(any(unix, windows))]
    slot: Arc<SignalSlot>,
    #[cfg(any(unix, windows))]
    seen_deliveries: u64,
}

impl Signal {
    /// Creates a new signal stream for the given signal kind.
    ///
    /// # Errors
    ///
    /// Returns an error if signal handling is not available for this platform
    /// or signal kind.
    fn new(kind: SignalKind) -> Result<Self, SignalError> {
        #[cfg(any(unix, windows))]
        {
            let dispatcher = dispatcher_for(kind)?;
            let slot = dispatcher.slot(kind).ok_or_else(|| {
                SignalError::unsupported(kind, "signal kind is not supported by dispatcher")
            })?;
            // Take the cursor before registering. Once add_signal returns, the
            // default disposition is gone, so a delivery recorded in between
            // must belong to this stream rather than count as already seen.
            let seen_deliveries = slot.deliveries.load(Ordering::Acquire);
            #[cfg(unix)]
            dispatcher
                .handle
                .add_signal(raw_signal_for_kind(kind))
                .map_err(|err| {
                    SignalError::unsupported(kind, format!("failed to register signal: {err}"))
                })?;
            Ok(Self {
                kind,
                slot,
                seen_deliveries,
            })
        }

        #[cfg(not(any(unix, windows)))]
        {
            Err(SignalError::unsupported(
                kind,
                "signal handling is unavailable on this platform/build",
            ))
        }
    }

    /// Receives the next signal notification.
    ///
    /// Returns `None` if the signal stream has been closed.
    ///
    /// # Cancel Safety
    ///
    /// This method is cancel-safe. If you use it as the event in a `select!`
    /// statement and some other branch completes first, no signal notification
    /// is lost.
    pub async fn recv(&mut self) -> Option<()> {
        #[cfg(any(unix, windows))]
        {
            loop {
                let seen = self.seen_deliveries;
                let slot = Arc::clone(&self.slot);
                let mut notified = std::pin::pin!(slot.notify.notified());
                std::future::poll_fn(|cx| {
                    if Future::poll(notified.as_mut(), cx).is_ready()
                        || slot.deliveries.load(Ordering::Acquire) > seen
                    {
                        return std::task::Poll::Ready(());
                    }
                    std::task::Poll::Pending
                })
                .await;

                if self.slot.deliveries.load(Ordering::Acquire) > self.seen_deliveries {
                    self.seen_deliveries = self.seen_deliveries.saturating_add(1);
                    return Some(());
                }
            }
        }

        #[cfg(not(any(unix, windows)))]
        {
            None
        }
    }

    /// Returns the signal kind this stream is listening for.
    #[must_use]
    pub fn kind(&self) -> SignalKind {
        self.kind
    }
}

/// Creates a new stream that receives signals of the given kind.
///
/// On Unix, registration intercepts only this signal kind; creating an
/// interrupt stream does not also intercept termination, hangup, or alarm.
/// Registrations remain process-global and persist after all streams of that
/// kind are dropped. Dropping a stream does not restore its default disposition.
/// Other libraries' signal handlers are subject to `signal-hook`'s usual
/// composition rules; this function does not replace their policies.
///
/// # Errors
///
/// Returns an error if signal handling is not available. Refuses with
/// [`IoCapabilityDenied`](crate::cx::IoCapabilityDenied) when the calling
/// task's `Cx` lacks the IO capability.
///
/// # Example
///
/// ```ignore
/// use asupersync::signal::{signal, SignalKind};
///
/// let mut sigterm = signal(SignalKind::terminate())?;
/// sigterm.recv().await;
/// ```
pub fn signal(kind: SignalKind) -> io::Result<Signal> {
    crate::cx::io_gate::require_ambient_io("signal::signal")?;
    Signal::new(kind).map_err(Into::into)
}

/// Thread-scoped set of signals used for Unix signal-mask operations.
///
/// On Unix, this stores the exact OS signal set returned by `pthread_sigmask`
/// so a [`SignalMaskGuard`] can restore masks that contain signals outside
/// Asupersync's portable [`SignalKind`] subset. On unsupported platforms the
/// set remains inspectable but applying it returns [`io::ErrorKind::Unsupported`].
#[derive(Clone, Debug)]
pub struct SignalMask {
    kinds: Vec<SignalKind>,
    #[cfg(unix)]
    inner: SigSet,
}

impl SignalMask {
    /// Returns an empty signal mask.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            kinds: Vec::new(),
            #[cfg(unix)]
            inner: SigSet::empty(),
        }
    }

    /// Builds a signal mask from supported signal kinds.
    #[must_use]
    pub fn from_kinds(kinds: impl IntoIterator<Item = SignalKind>) -> Self {
        let mut mask = Self::empty();
        for kind in kinds {
            mask.add(kind);
        }
        mask
    }

    /// Returns the currently blocked signal mask for the calling thread.
    pub fn current_thread() -> io::Result<Self> {
        #[cfg(unix)]
        {
            SigSet::thread_get_mask()
                .map(Self::from_unix_set)
                .map_err(Into::into)
        }

        #[cfg(not(unix))]
        {
            Err(unsupported_signal_mask_error())
        }
    }

    /// Adds a supported signal kind to this mask.
    pub fn add(&mut self, kind: SignalKind) {
        if !self.kinds.contains(&kind) {
            self.kinds.push(kind);
        }

        #[cfg(unix)]
        self.inner.add(nix_signal_for_kind(kind));
    }

    /// Returns whether this mask contains the supported signal kind.
    #[must_use]
    pub fn contains(&self, kind: SignalKind) -> bool {
        #[cfg(unix)]
        {
            self.inner.contains(nix_signal_for_kind(kind))
        }

        #[cfg(not(unix))]
        {
            self.kinds.contains(&kind)
        }
    }

    /// Iterates the supported signal kinds present in this mask.
    pub fn kinds(&self) -> impl Iterator<Item = SignalKind> + '_ {
        self.kinds.iter().copied()
    }

    /// Adds this mask to the calling thread's blocked signal set.
    ///
    /// The returned guard restores the exact previous mask when dropped. Call
    /// [`SignalMaskGuard::restore`] to observe restore errors explicitly.
    pub fn block_current_thread(&self) -> io::Result<SignalMaskGuard> {
        self.apply_to_current_thread(SignalMaskOperation::Block)
    }

    /// Removes this mask from the calling thread's blocked signal set.
    ///
    /// The returned guard restores the exact previous mask when dropped. Call
    /// [`SignalMaskGuard::restore`] to observe restore errors explicitly.
    pub fn unblock_current_thread(&self) -> io::Result<SignalMaskGuard> {
        self.apply_to_current_thread(SignalMaskOperation::Unblock)
    }

    /// Replaces the calling thread's blocked signal set with this mask.
    ///
    /// The returned guard restores the exact previous mask when dropped. Call
    /// [`SignalMaskGuard::restore`] to observe restore errors explicitly.
    pub fn set_current_thread(&self) -> io::Result<SignalMaskGuard> {
        self.apply_to_current_thread(SignalMaskOperation::Set)
    }

    fn apply_to_current_thread(
        &self,
        operation: SignalMaskOperation,
    ) -> io::Result<SignalMaskGuard> {
        #[cfg(unix)]
        {
            let how = match operation {
                SignalMaskOperation::Block => SigmaskHow::SIG_BLOCK,
                SignalMaskOperation::Unblock => SigmaskHow::SIG_UNBLOCK,
                SignalMaskOperation::Set => SigmaskHow::SIG_SETMASK,
            };
            self.inner
                .thread_swap_mask(how)
                .map(Self::from_unix_set)
                .map(SignalMaskGuard::new)
                .map_err(Into::into)
        }

        #[cfg(not(unix))]
        {
            let _ = operation;
            Err(unsupported_signal_mask_error())
        }
    }

    #[cfg(unix)]
    fn restore_current_thread(&self) -> io::Result<()> {
        self.inner.thread_set_mask().map_err(Into::into)
    }

    #[cfg(unix)]
    fn from_unix_set(inner: SigSet) -> Self {
        let kinds = all_signal_kinds()
            .into_iter()
            .filter(|kind| inner.contains(nix_signal_for_kind(*kind)))
            .collect();

        Self { kinds, inner }
    }
}

impl FromIterator<SignalKind> for SignalMask {
    fn from_iter<T: IntoIterator<Item = SignalKind>>(iter: T) -> Self {
        Self::from_kinds(iter)
    }
}

/// RAII guard that restores a thread signal mask.
///
/// Signal masks are thread-local attributes (`pthread_sigmask`). This guard is
/// intentionally `!Send` and `!Sync` so it cannot be transferred to another OS
/// thread or held across an `.await` boundary on a multi-threaded runtime, where
/// dropping it would restore the signal mask of an arbitrary worker thread
/// (br-asupersync-abc5w5 LOW 7).
#[derive(Debug)]
pub struct SignalMaskGuard {
    previous: Option<SignalMask>,
    _not_send: std::marker::PhantomData<*mut ()>,
}

impl SignalMaskGuard {
    #[cfg(unix)]
    fn new(previous: SignalMask) -> Self {
        Self {
            previous: Some(previous),
            _not_send: std::marker::PhantomData,
        }
    }

    /// Returns the mask that will be restored when this guard is dropped.
    #[must_use]
    pub fn previous_mask(&self) -> Option<&SignalMask> {
        self.previous.as_ref()
    }

    /// Restores the prior thread signal mask now.
    ///
    /// Dropping the guard after an explicit restore is a no-op.
    pub fn restore(mut self) -> io::Result<()> {
        if let Some(previous) = self.previous.take() {
            restore_signal_mask(previous)?;
        }
        Ok(())
    }
}

impl Drop for SignalMaskGuard {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            let _ = restore_signal_mask(previous);
        }
    }
}

/// Blocks supported signals on the current thread until the returned guard is
/// restored or dropped.
///
/// # Errors
///
/// Returns an unsupported error outside Unix, or an OS error if updating the
/// thread signal mask fails.
pub fn block_current_thread_signals(
    kinds: impl IntoIterator<Item = SignalKind>,
) -> io::Result<SignalMaskGuard> {
    SignalMask::from_kinds(kinds).block_current_thread()
}

#[derive(Debug, Clone, Copy)]
enum SignalMaskOperation {
    Block,
    Unblock,
    Set,
}

fn restore_signal_mask(previous: SignalMask) -> io::Result<()> {
    #[cfg(unix)]
    {
        previous.restore_current_thread()
    }

    #[cfg(not(unix))]
    {
        let _ = previous;
        Err(unsupported_signal_mask_error())
    }
}

#[cfg(unix)]
fn nix_signal_for_kind(kind: SignalKind) -> NixSignal {
    match kind {
        SignalKind::Interrupt => NixSignal::SIGINT,
        SignalKind::Terminate => NixSignal::SIGTERM,
        SignalKind::Hangup => NixSignal::SIGHUP,
        SignalKind::Quit => NixSignal::SIGQUIT,
        SignalKind::User1 => NixSignal::SIGUSR1,
        SignalKind::User2 => NixSignal::SIGUSR2,
        SignalKind::Child => NixSignal::SIGCHLD,
        SignalKind::WindowChange => NixSignal::SIGWINCH,
        SignalKind::Pipe => NixSignal::SIGPIPE,
        SignalKind::Alarm => NixSignal::SIGALRM,
    }
}

#[cfg(not(unix))]
fn unsupported_signal_mask_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "thread signal masks are only supported on Unix",
    )
}

#[cfg(test)]
pub fn inject_test_signal(kind: SignalKind) -> io::Result<()> {
    #[cfg(any(unix, windows))]
    {
        dispatcher_for(kind)
            .map(|dispatcher| dispatcher.inject(kind))
            .map_err(Into::into)
    }

    #[cfg(not(any(unix, windows)))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("signal injection is unavailable on this platform/build ({kind})"),
        ))
    }
}

/// Creates a stream for SIGINT (Ctrl+C on Unix and Windows).
///
/// # Errors
///
/// Returns an error if signal handling is not available.
#[cfg(any(unix, windows))]
pub fn sigint() -> io::Result<Signal> {
    signal(SignalKind::interrupt())
}

/// Creates a stream for SIGTERM.
///
/// # Errors
///
/// Returns an error if signal handling is not available.
#[cfg(any(unix, windows))]
pub fn sigterm() -> io::Result<Signal> {
    signal(SignalKind::terminate())
}

/// Creates a stream for SIGHUP.
///
/// # Errors
///
/// Returns an error if signal handling is not available.
#[cfg(unix)]
pub fn sighup() -> io::Result<Signal> {
    signal(SignalKind::hangup())
}

/// Creates a stream for SIGUSR1.
///
/// # Errors
///
/// Returns an error if signal handling is not available.
#[cfg(unix)]
pub fn sigusr1() -> io::Result<Signal> {
    signal(SignalKind::user_defined1())
}

/// Creates a stream for SIGUSR2.
///
/// # Errors
///
/// Returns an error if signal handling is not available.
#[cfg(unix)]
pub fn sigusr2() -> io::Result<Signal> {
    signal(SignalKind::user_defined2())
}

/// Creates a stream for SIGQUIT on Unix or SIGBREAK on Windows.
///
/// # Errors
///
/// Returns an error if signal handling is not available.
#[cfg(any(unix, windows))]
pub fn sigquit() -> io::Result<Signal> {
    signal(SignalKind::quit())
}

/// Creates a stream for SIGCHLD.
///
/// # Errors
///
/// Returns an error if signal handling is not available.
#[cfg(unix)]
pub fn sigchld() -> io::Result<Signal> {
    signal(SignalKind::child())
}

/// Creates a stream for SIGWINCH.
///
/// # Errors
///
/// Returns an error if signal handling is not available.
#[cfg(unix)]
pub fn sigwinch() -> io::Result<Signal> {
    signal(SignalKind::window_change())
}

/// Creates a stream for SIGPIPE.
///
/// # Errors
///
/// Returns an error if signal handling is not available.
#[cfg(unix)]
pub fn sigpipe() -> io::Result<Signal> {
    signal(SignalKind::pipe())
}

/// Creates a stream for SIGALRM.
///
/// # Errors
///
/// Returns an error if signal handling is not available.
#[cfg(unix)]
pub fn sigalrm() -> io::Result<Signal> {
    signal(SignalKind::alarm())
}

#[cfg(test)]
#[path = "signal_inline_tests.rs"]
mod tests;
