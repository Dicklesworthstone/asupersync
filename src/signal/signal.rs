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
    #[allow(unsafe_code)] // signal_hook::low_level::register requires unsafe
    fn start() -> io::Result<Self> {
        let mut slots = HashMap::with_capacity(4);
        for kind in all_signal_kinds() {
            slots.insert(kind, Arc::new(SignalSlot::new()));
        }

        // On Windows, signal_hook::iterator is unavailable. Use low-level
        // register() which installs CRT signal handlers that invoke our
        // callback directly.
        //
        // IMPORTANT: CRT signal handlers run in signal context where locking
        // is forbidden. We use `record_delivery_signal_safe` (atomic-only) in
        // the handler and spawn a background poller thread to call
        // `notify_waiters` from a safe context.
        for kind in all_signal_kinds() {
            let raw = raw_signal_for_kind(kind);
            let slot = slots.get(&kind).expect("slot just inserted").clone();
            // SAFETY: our closure only touches an atomic counter — no
            // allocations, locks, or non-reentrant calls.
            unsafe {
                signal_hook::low_level::register(raw, move || {
                    slot.record_delivery_signal_safe();
                })?;
            }
        }

        // Background thread polls atomic counters and wakes async waiters
        // from a safe (non-signal) context.
        let poller_slots: Vec<Arc<SignalSlot>> = slots.values().cloned().collect();
        thread::Builder::new()
            .name("asupersync-signal-poll-win".to_string())
            .spawn(move || {
                let mut last_seen: Vec<u64> = vec![0; poller_slots.len()];
                loop {
                    thread::sleep(std::time::Duration::from_millis(1));
                    for (i, slot) in poller_slots.iter().enumerate() {
                        last_seen[i] = slot.notify_if_changed(last_seen[i]);
                    }
                }
            })
            .map_err(|e| io::Error::other(format!("failed to spawn signal poller: {e}")))?;

        Ok(Self { slots })
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
    use super::*;
    use std::future::Future;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
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
}
