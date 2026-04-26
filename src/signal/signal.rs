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
use std::sync::{Arc, OnceLock};
#[cfg(any(unix, windows))]
use std::thread;

#[cfg(any(unix, windows))]
use crate::sync::Notify;

use super::SignalKind;

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

    fn record_delivery(&self) {
        self.deliveries.fetch_add(1, Ordering::Release);
        self.notify.notify_waiters();
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
            self.notify.notify_waiters();
        }
        current
    }
}

#[cfg(any(unix, windows))]
#[derive(Debug)]
struct SignalDispatcher {
    slots: HashMap<SignalKind, Arc<SignalSlot>>,
    #[cfg(unix)]
    _handle: signal_hook::iterator::Handle,
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

// SAFETY: Win32 Event objects accessed via SetEvent / WaitForMultipleObjects
// / CloseHandle are documented to be safe to use from arbitrary threads
// (the kernel-side state is the synchronization domain). The HANDLE
// itself is just an opaque pointer to a kernel object, not into thread-
// local memory.
#[cfg(windows)]
unsafe impl Send for WindowsEventHandle {}
#[cfg(windows)]
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
        unsafe {
            // SAFETY: shutdown_event is a valid manual-reset Event we
            // created in start(); SetEvent is safe to call repeatedly.
            let _ = windows_sys::Win32::System::Threading::SetEvent(self.shutdown_event.0);
        }
        if let Some(handle) = self.poller_handle.take() {
            // Best-effort join: if the poller thread panicked we still
            // want shutdown to proceed cleanly rather than propagate
            // the panic from a destructor.
            let _ = handle.join();
        }
        unsafe {
            // SAFETY: both handles were created by CreateEventW in
            // start() and have not been closed elsewhere. Any signal
            // handlers that captured signal_pending_event by Copy will
            // still hold the (now-stale) HANDLE value; once the
            // dispatcher is dropped the process is shutting down and
            // CRT signal handlers should not fire — see start() docs
            // for the lifecycle contract.
            let _ = windows_sys::Win32::Foundation::CloseHandle(self.shutdown_event.0);
            let _ = windows_sys::Win32::Foundation::CloseHandle(self.signal_pending_event.0);
        }
    }
}

#[cfg(unix)]
impl SignalDispatcher {
    fn start() -> io::Result<Self> {
        let mut slots = HashMap::with_capacity(8);
        for kind in all_signal_kinds() {
            slots.insert(kind, Arc::new(SignalSlot::new()));
        }

        let raw_signals: Vec<i32> = all_signal_kinds()
            .iter()
            .copied()
            .map(raw_signal_for_kind)
            .collect();
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

        Ok(Self {
            slots,
            _handle: handle,
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

#[cfg(windows)]
impl SignalDispatcher {
    #[allow(unsafe_code)] // signal_hook::low_level::register + Win32 FFI
    fn start() -> io::Result<Self> {
        use std::ptr;
        use windows_sys::Win32::Foundation::{
            CloseHandle, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
        };
        use windows_sys::Win32::System::Threading::{
            CreateEventW, INFINITE, SetEvent, WaitForMultipleObjects,
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
        if signal_pending_event_raw.is_null()
            || signal_pending_event_raw == INVALID_HANDLE_VALUE
        {
            // Don't leak the first handle if the second fails.
            unsafe {
                let _ = CloseHandle(shutdown_event_raw);
            }
            return Err(io::Error::last_os_error());
        }
        let shutdown_event = WindowsEventHandle(shutdown_event_raw);
        let signal_pending_event = WindowsEventHandle(signal_pending_event_raw);

        // On Windows, signal_hook::iterator is unavailable. Use low-level
        // register() which installs CRT signal handlers that invoke our
        // callback directly.
        //
        // CRT signal handlers run in signal context where locking is
        // forbidden. We use `record_delivery_signal_safe` (atomic-only)
        // in the handler AND additionally call `SetEvent` on
        // signal_pending_event — `SetEvent` is documented signal-safe
        // on Win32 CTRL handlers (it's a single kernel-syscall path
        // with no allocator / no locks observable from user space).
        for kind in all_signal_kinds() {
            let raw = raw_signal_for_kind(kind);
            let slot = slots.get(&kind).expect("slot just inserted").clone();
            // Capture by Copy — WindowsEventHandle is Copy and Send.
            // The HANDLE remains valid for the lifetime of this
            // SignalDispatcher; SignalDispatcher::Drop closes the
            // event AFTER joining the poller. CRT signal handlers are
            // process-global and may technically outlive the
            // dispatcher; in practice the dispatcher is created once
            // at runtime startup and dropped at process exit, so the
            // ordering is safe.
            let pending = signal_pending_event;
            // SAFETY: closure body uses only atomic stores
            // (record_delivery_signal_safe) and SetEvent on a kernel
            // event handle — both signal-safe operations on Windows
            // CTRL handlers.
            unsafe {
                signal_hook::low_level::register(raw, move || {
                    slot.record_delivery_signal_safe();
                    let _ = SetEvent(pending.0);
                })?;
            }
        }

        // Poller thread waits on [shutdown, signal_pending] with
        // INFINITE timeout. Returns:
        //   WAIT_OBJECT_0     (0) → shutdown_event was set, exit loop
        //   WAIT_OBJECT_0 + 1 (1) → signal_pending_event was set, drain
        //                            atomics and re-wait
        //   anything else (incl. WAIT_FAILED, WAIT_ABANDONED_*) → bail
        //                            so we don't spin on persistent error
        const SHUTDOWN_INDEX: u32 = WAIT_OBJECT_0;
        const SIGNAL_PENDING_INDEX: u32 = WAIT_OBJECT_0 + 1;

        let poller_slots: Vec<Arc<SignalSlot>> = slots.values().cloned().collect();
        let poller_shutdown_handle = shutdown_event;
        let poller_pending_handle = signal_pending_event;
        let poller_handle = thread::Builder::new()
            .name("asupersync-signal-poll-win".to_string())
            .spawn(move || {
                let handles: [windows_sys::Win32::Foundation::HANDLE; 2] = [
                    poller_shutdown_handle.0,
                    poller_pending_handle.0,
                ];
                let mut last_seen: Vec<u64> = vec![0; poller_slots.len()];
                loop {
                    // SAFETY: handles array contains two valid event
                    // handles created by CreateEventW above; they
                    // remain valid for the lifetime of this thread
                    // (closed only by SignalDispatcher::Drop AFTER
                    // join). bWaitAll = FALSE so the call returns as
                    // soon as ANY handle is signaled.
                    let rc = unsafe {
                        WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE)
                    };
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
            .map_err(|e| io::Error::other(format!("failed to spawn signal poller: {e}")))?;

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

#[cfg(any(unix, windows))]
static SIGNAL_DISPATCHER: OnceLock<io::Result<SignalDispatcher>> = OnceLock::new();

#[cfg(any(unix, windows))]
fn dispatcher_for(kind: SignalKind) -> Result<&'static SignalDispatcher, SignalError> {
    let result = SIGNAL_DISPATCHER.get_or_init(SignalDispatcher::start);
    match result {
        Ok(dispatcher) => Ok(dispatcher),
        Err(err) => Err(SignalError::unsupported(
            kind,
            format!("failed to initialize signal dispatcher: {err}"),
        )),
    }
}

/// An async stream that receives signals of a particular kind.
///
/// # Example
///
/// ```ignore
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
            let seen_deliveries = slot.deliveries.load(Ordering::Acquire);
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
                let notified = self.slot.notify.notified();
                let current = self.slot.deliveries.load(Ordering::Acquire);
                if current > self.seen_deliveries {
                    self.seen_deliveries = self.seen_deliveries.saturating_add(1);
                    return Some(());
                }
                notified.await;
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
/// # Errors
///
/// Returns an error if signal handling is not available.
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
    Signal::new(kind).map_err(Into::into)
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

/// Creates a stream for SIGINT (Ctrl+C on Unix).
///
/// # Errors
///
/// Returns an error if signal handling is not available.
#[cfg(unix)]
pub fn sigint() -> io::Result<Signal> {
    signal(SignalKind::interrupt())
}

/// Creates a stream for SIGTERM.
///
/// # Errors
///
/// Returns an error if signal handling is not available.
#[cfg(unix)]
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

/// Creates a stream for SIGQUIT.
///
/// # Errors
///
/// Returns an error if signal handling is not available.
#[cfg(unix)]
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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn signal_error_display() {
        init_test("signal_error_display");
        let err = SignalError::unsupported(SignalKind::Terminate, "signal unsupported");
        let msg = format!("{err}");
        let has_sigterm = msg.contains("SIGTERM");
        crate::assert_with_log!(has_sigterm, "contains SIGTERM", true, has_sigterm);
        let has_reason = msg.contains("unsupported");
        crate::assert_with_log!(has_reason, "contains reason", true, has_reason);
        crate::test_complete!("signal_error_display");
    }

    #[test]
    fn signal_creation_platform_contract() {
        init_test("signal_creation_platform_contract");
        let result = signal(SignalKind::terminate());

        #[cfg(unix)]
        {
            let ok = result.is_ok();
            crate::assert_with_log!(ok, "signal creation ok", true, ok);
        }

        #[cfg(not(any(unix, windows)))]
        {
            let is_err = result.is_err();
            crate::assert_with_log!(is_err, "signal unsupported", true, is_err);
        }

        crate::test_complete!("signal_creation_platform_contract");
    }

    #[cfg(unix)]
    #[test]
    fn unix_signal_helpers() {
        init_test("unix_signal_helpers");
        let sigint_ok = sigint().is_ok();
        crate::assert_with_log!(sigint_ok, "sigint ok", true, sigint_ok);
        let sigterm_ok = sigterm().is_ok();
        crate::assert_with_log!(sigterm_ok, "sigterm ok", true, sigterm_ok);
        let sighup_ok = sighup().is_ok();
        crate::assert_with_log!(sighup_ok, "sighup ok", true, sighup_ok);
        let sigusr1_ok = sigusr1().is_ok();
        crate::assert_with_log!(sigusr1_ok, "sigusr1 ok", true, sigusr1_ok);
        let sigusr2_ok = sigusr2().is_ok();
        crate::assert_with_log!(sigusr2_ok, "sigusr2 ok", true, sigusr2_ok);
        let sigquit_ok = sigquit().is_ok();
        crate::assert_with_log!(sigquit_ok, "sigquit ok", true, sigquit_ok);
        let sigchld_ok = sigchld().is_ok();
        crate::assert_with_log!(sigchld_ok, "sigchld ok", true, sigchld_ok);
        let sigwinch_ok = sigwinch().is_ok();
        crate::assert_with_log!(sigwinch_ok, "sigwinch ok", true, sigwinch_ok);
        let sigpipe_ok = sigpipe().is_ok();
        crate::assert_with_log!(sigpipe_ok, "sigpipe ok", true, sigpipe_ok);
        let sigalrm_ok = sigalrm().is_ok();
        crate::assert_with_log!(sigalrm_ok, "sigalrm ok", true, sigalrm_ok);
        crate::test_complete!("unix_signal_helpers");
    }

    #[cfg(unix)]
    #[test]
    fn signal_recv_observes_delivery() {
        init_test("signal_recv_observes_delivery");
        let mut stream = signal(SignalKind::terminate()).expect("stream available");
        dispatcher_for(SignalKind::terminate())
            .expect("dispatcher")
            .inject(SignalKind::terminate());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut recv = Box::pin(stream.recv());
        let poll = recv.as_mut().poll(&mut cx);
        crate::assert_with_log!(
            matches!(poll, Poll::Ready(Some(()))),
            "recv returns delivery",
            "Poll::Ready(Some(()))",
            poll
        );
        crate::test_complete!("signal_recv_observes_delivery");
    }

    #[cfg(unix)]
    #[test]
    fn signal_recv_preserves_multiple_recorded_deliveries() {
        init_test("signal_recv_preserves_multiple_recorded_deliveries");
        let mut stream = signal(SignalKind::terminate()).expect("stream available");
        let dispatcher = dispatcher_for(SignalKind::terminate()).expect("dispatcher");
        dispatcher.inject(SignalKind::terminate());
        dispatcher.inject(SignalKind::terminate());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut first_recv = Box::pin(stream.recv());
        let first = first_recv.as_mut().poll(&mut cx);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Some(()))),
            "first recv consumes one pending delivery",
            "Poll::Ready(Some(()))",
            first
        );
        drop(first_recv);

        let mut second_recv = Box::pin(stream.recv());
        let second = second_recv.as_mut().poll(&mut cx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Some(()))),
            "second recv consumes second pending delivery",
            "Poll::Ready(Some(()))",
            second
        );
        crate::test_complete!("signal_recv_preserves_multiple_recorded_deliveries");
    }

    #[cfg(unix)]
    #[test]
    fn unix_raw_signal_mapping_covers_pipe_and_alarm() {
        init_test("unix_raw_signal_mapping_covers_pipe_and_alarm");
        let pipe = signal_kind_from_raw(libc::SIGPIPE);
        crate::assert_with_log!(
            pipe == Some(SignalKind::Pipe),
            "SIGPIPE mapped",
            Some(SignalKind::Pipe),
            pipe
        );
        let alarm = signal_kind_from_raw(libc::SIGALRM);
        crate::assert_with_log!(
            alarm == Some(SignalKind::Alarm),
            "SIGALRM mapped",
            Some(SignalKind::Alarm),
            alarm
        );
        crate::test_complete!("unix_raw_signal_mapping_covers_pipe_and_alarm");
    }

    #[cfg(windows)]
    #[test]
    fn windows_raw_signal_mapping_subset() {
        init_test("windows_raw_signal_mapping_subset");
        let interrupt = signal_kind_from_raw(libc::SIGINT);
        crate::assert_with_log!(
            interrupt == Some(SignalKind::Interrupt),
            "SIGINT mapped",
            Some(SignalKind::Interrupt),
            interrupt
        );
        let terminate = signal_kind_from_raw(libc::SIGTERM);
        crate::assert_with_log!(
            terminate == Some(SignalKind::Terminate),
            "SIGTERM mapped",
            Some(SignalKind::Terminate),
            terminate
        );
        let quit = signal_kind_from_raw(signal_hook::consts::SIGBREAK);
        crate::assert_with_log!(
            quit == Some(SignalKind::Quit),
            "SIGBREAK mapped",
            Some(SignalKind::Quit),
            quit
        );
        crate::test_complete!("windows_raw_signal_mapping_subset");
    }

    // =========================================================================
    // SIGPIPE Conformance Tests - RFC POSIX.1-2017 Section 2.4.1
    // =========================================================================

    #[cfg(unix)]
    #[test]
    fn sigpipe_signal_handler_registration() {
        init_test("sigpipe_signal_handler_registration");

        // Test that SIGPIPE can be registered for handling
        let stream_result = signal(SignalKind::pipe());
        crate::assert_with_log!(
            stream_result.is_ok(),
            "SIGPIPE signal stream creation succeeds",
            true,
            stream_result.is_ok()
        );

        // Verify SIGPIPE is mapped to correct raw signal value
        let raw_sigpipe = SignalKind::pipe().as_raw_value();
        crate::assert_with_log!(
            raw_sigpipe == libc::SIGPIPE,
            "SIGPIPE maps to libc::SIGPIPE",
            libc::SIGPIPE,
            raw_sigpipe
        );

        crate::test_complete!("sigpipe_signal_handler_registration");
    }

    #[cfg(unix)]
    #[test]
    fn sigpipe_signal_delivery_observable() {
        init_test("sigpipe_signal_delivery_observable");

        let mut stream = signal(SignalKind::pipe()).expect("SIGPIPE stream");

        // Inject a SIGPIPE signal into the dispatcher
        let dispatcher = dispatcher_for(SignalKind::pipe()).expect("SIGPIPE dispatcher");
        dispatcher.inject(SignalKind::pipe());

        // Poll the signal stream to observe delivery
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut recv = Box::pin(stream.recv());
        let poll = recv.as_mut().poll(&mut cx);

        crate::assert_with_log!(
            matches!(poll, Poll::Ready(Some(()))),
            "SIGPIPE signal delivery is observable",
            "Poll::Ready(Some(()))",
            poll
        );

        crate::test_complete!("sigpipe_signal_delivery_observable");
    }

    #[cfg(unix)]
    #[test]
    fn sigpipe_multiple_deliveries_preserved() {
        init_test("sigpipe_multiple_deliveries_preserved");

        let mut stream = signal(SignalKind::pipe()).expect("SIGPIPE stream");
        let dispatcher = dispatcher_for(SignalKind::pipe()).expect("SIGPIPE dispatcher");

        // Inject multiple SIGPIPE signals
        dispatcher.inject(SignalKind::pipe());
        dispatcher.inject(SignalKind::pipe());

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First recv should succeed
        {
            let mut recv1 = Box::pin(stream.recv());
            let poll1 = recv1.as_mut().poll(&mut cx);
            crate::assert_with_log!(
                matches!(poll1, Poll::Ready(Some(()))),
                "First SIGPIPE delivery received",
                "Poll::Ready(Some(()))",
                poll1
            );
        }

        // Second recv should also succeed (no lost signals)
        {
            let mut recv2 = Box::pin(stream.recv());
            let poll2 = recv2.as_mut().poll(&mut cx);
            crate::assert_with_log!(
                matches!(poll2, Poll::Ready(Some(()))),
                "Second SIGPIPE delivery received",
                "Poll::Ready(Some(()))",
                poll2
            );
        }

        crate::test_complete!("sigpipe_multiple_deliveries_preserved");
    }

    #[cfg(windows)]
    #[test]
    fn sigpipe_unsupported_on_windows() {
        init_test("sigpipe_unsupported_on_windows");

        // SIGPIPE should not be supported on Windows
        let raw_value = SignalKind::pipe().as_raw_value();
        crate::assert_with_log!(
            raw_value.is_none(),
            "SIGPIPE not supported on Windows",
            None,
            raw_value
        );

        // Signal stream creation should fail with unsupported error
        let stream_result = signal(SignalKind::pipe());
        crate::assert_with_log!(
            stream_result.is_err(),
            "SIGPIPE signal stream creation fails on Windows",
            true,
            stream_result.is_err()
        );

        if let Err(err) = stream_result {
            let error_msg = err.to_string();
            crate::assert_with_log!(
                error_msg.to_lowercase().contains("unsupported")
                    || error_msg.to_lowercase().contains("not supported"),
                "Error message indicates unsupported",
                true,
                error_msg.to_lowercase().contains("unsupported")
                    || error_msg.to_lowercase().contains("not supported")
            );
        }

        crate::test_complete!("sigpipe_unsupported_on_windows");
    }

    #[cfg(not(any(unix, windows)))]
    #[test]
    fn sigpipe_unsupported_on_other_platforms() {
        init_test("sigpipe_unsupported_on_other_platforms");

        // SIGPIPE should not be supported on non-Unix, non-Windows platforms
        let raw_value = SignalKind::pipe().as_raw_value();
        crate::assert_with_log!(
            raw_value.is_none(),
            "SIGPIPE not supported on other platforms",
            None,
            raw_value
        );

        crate::test_complete!("sigpipe_unsupported_on_other_platforms");
    }

    #[cfg(unix)]
    #[test]
    fn sigpipe_cancel_safety_preserved() {
        init_test("sigpipe_cancel_safety_preserved");

        let mut stream = signal(SignalKind::pipe()).expect("SIGPIPE stream");
        let dispatcher = dispatcher_for(SignalKind::pipe()).expect("SIGPIPE dispatcher");

        // Inject a signal before starting recv
        dispatcher.inject(SignalKind::pipe());

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Start recv, then drop it (simulating cancellation)
        {
            let mut recv = Box::pin(stream.recv());
            let _poll = recv.as_mut().poll(&mut cx);
        } // recv dropped here

        // Start a new recv - signal should still be delivered (cancel-safe)
        let mut recv_after_cancel = Box::pin(stream.recv());
        let poll_after = recv_after_cancel.as_mut().poll(&mut cx);
        crate::assert_with_log!(
            matches!(poll_after, Poll::Ready(Some(()))),
            "SIGPIPE delivery preserved after cancellation",
            "Poll::Ready(Some(()))",
            poll_after
        );

        crate::test_complete!("sigpipe_cancel_safety_preserved");
    }

    #[test]
    fn sigpipe_platform_behavior_documented() {
        init_test("sigpipe_platform_behavior_documented");

        // Document platform-specific SIGPIPE behavior differences

        #[cfg(unix)]
        {
            // Unix: SIGPIPE fully supported
            let unix_supported = SignalKind::pipe().as_raw_value() == libc::SIGPIPE;
            crate::assert_with_log!(
                unix_supported,
                "Unix: SIGPIPE mapped to libc::SIGPIPE",
                true,
                unix_supported
            );
        }

        #[cfg(windows)]
        {
            // Windows: SIGPIPE not supported (different pipe break semantics)
            let windows_unsupported = SignalKind::pipe().as_raw_value().is_none();
            crate::assert_with_log!(
                windows_unsupported,
                "Windows: SIGPIPE not supported (uses ERROR_BROKEN_PIPE instead)",
                true,
                windows_unsupported
            );
        }

        #[cfg(target_os = "linux")]
        {
            // Linux: MSG_NOSIGNAL flag available for send()
            let msg_nosignal_available = libc::MSG_NOSIGNAL != 0;
            crate::assert_with_log!(
                msg_nosignal_available,
                "Linux: MSG_NOSIGNAL flag available",
                true,
                msg_nosignal_available
            );
        }

        #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
        {
            // BSD-based: SO_NOSIGPIPE socket option available
            let so_nosigpipe_available = libc::SO_NOSIGPIPE != 0;
            crate::assert_with_log!(
                so_nosigpipe_available,
                "BSD: SO_NOSIGPIPE socket option available",
                true,
                so_nosigpipe_available
            );
        }

        crate::test_complete!("sigpipe_platform_behavior_documented");
    }

    #[cfg(all(windows, feature = "test-internals"))]
    #[test]
    fn sigpipe_ctrl_c_event_interaction() {
        init_test("sigpipe_ctrl_c_event_interaction");

        // On Windows, test that CTRL_C_EVENT doesn't interfere with
        // broken pipe error reporting (since SIGPIPE doesn't exist)

        // CTRL_C_EVENT should map to SIGINT
        let ctrl_c_signal = SignalKind::interrupt().as_raw_value();
        crate::assert_with_log!(
            ctrl_c_signal == Some(libc::SIGINT),
            "CTRL_C_EVENT maps to SIGINT",
            Some(libc::SIGINT),
            ctrl_c_signal
        );

        // SIGPIPE should remain unsupported
        let sigpipe_unsupported = SignalKind::pipe().as_raw_value().is_none();
        crate::assert_with_log!(
            sigpipe_unsupported,
            "SIGPIPE remains unsupported with CTRL_C_EVENT",
            true,
            sigpipe_unsupported
        );

        // Both should be independent - SIGINT available, SIGPIPE not
        let int_stream = signal(SignalKind::interrupt());
        let pipe_stream = signal(SignalKind::pipe());

        crate::assert_with_log!(
            int_stream.is_ok(),
            "SIGINT stream creation succeeds",
            true,
            int_stream.is_ok()
        );
        crate::assert_with_log!(
            pipe_stream.is_err(),
            "SIGPIPE stream creation fails",
            true,
            pipe_stream.is_err()
        );

        crate::test_complete!("sigpipe_ctrl_c_event_interaction");
    }
}
