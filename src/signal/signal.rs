//! Async signal streams for Unix signals.
//!
//! # Cancel Safety
//!
//! - `Signal::recv`: cancel-safe, no delivered signal notification is lost.
//!
//! # Design
//!
//! On Unix, a global dispatcher thread is installed once and receives process
//! signals via `signal-hook`. Delivered signals are fanned out to per-kind async
//! waiters using `Notify` + monotone delivery counters.

use std::io;

#[cfg(unix)]
use std::collections::HashMap;
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(unix)]
use std::sync::{Arc, OnceLock};
#[cfg(unix)]
use std::thread;

#[cfg(unix)]
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

#[cfg(unix)]
#[derive(Debug)]
struct SignalSlot {
    deliveries: AtomicU64,
    notify: Notify,
}

#[cfg(unix)]
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
}

#[cfg(unix)]
#[derive(Debug)]
struct SignalDispatcher {
    slots: HashMap<SignalKind, Arc<SignalSlot>>,
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
            .map(SignalKind::as_raw_value)
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

#[cfg(unix)]
static SIGNAL_DISPATCHER: OnceLock<io::Result<SignalDispatcher>> = OnceLock::new();

#[cfg(unix)]
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
    #[cfg(unix)]
    slot: Arc<SignalSlot>,
    #[cfg(unix)]
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
        #[cfg(unix)]
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

        #[cfg(not(unix))]
        {
            Err(SignalError::unsupported(
                kind,
                "signal handling is only available on Unix in this build",
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
        #[cfg(unix)]
        {
            loop {
                let current = self.slot.deliveries.load(Ordering::Acquire);
                if current > self.seen_deliveries {
                    self.seen_deliveries = current;
                    return Some(());
                }
                self.slot.notify.notified().await;
            }
        }

        #[cfg(not(unix))]
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

        #[cfg(not(unix))]
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
        let got = futures_lite::future::block_on(stream.recv());
        crate::assert_with_log!(got.is_some(), "recv returns delivery", true, got.is_some());
        crate::test_complete!("signal_recv_observes_delivery");
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
}
