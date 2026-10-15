//! Reactor conformance suite, driven against the production reactors.
//!
//! Every row drives the [`Reactor`] trait object (`&dyn Reactor`, or an
//! `Arc<dyn Reactor>` when a contract needs a second thread) over real
//! descriptors from `std::os::unix::net::UnixStream::pair()`, set nonblocking.
//!
//! | Row prefix           | Backend          | Runs when                                             |
//! |----------------------|------------------|-------------------------------------------------------|
//! | `epoll/`             | `EpollReactor`   | Linux                                                 |
//! | `io_uring/`          | `IoUringReactor` | Linux, `io-uring` feature, and the host grants a ring |
//! | `io_uring_vs_epoll/` | differential     | whenever both rows above ran                          |
//! | `lab/`               | `LabReactor`     | Unix and Windows, for the contracts it can express    |
//!
//! A differential row compares what the two kernel backends observably did
//! for one contract and fails, naming both behaviours and the implementing
//! code, whenever they differ. A backend that is not compiled into this build,
//! or that the host refuses to construct, contributes one
//! `<prefix>backend_available` row whose verdict is `Skip`; it never
//! contributes a `Pass`.
//!
//! One io_uring divergence is tracked (`known_gap`): asupersync-2mc31r
//! (`register` waits for a blocked `poll`). Its io_uring row and differential
//! report `TestVerdict::ExpectedGap` only when the observation matches the gap
//! exactly and conforms in every other check; a conforming backend passes and
//! is remarked as having closed the gap, and any other observation fails.
//! Every other row is strict, including the edge-triggered rows: io_uring
//! serves `EDGE_TRIGGERED` with a multishot poll since asupersync-ubwvb0, so
//! a new edge after a drain must arrive there as it does on epoll.
//!
//! Contracts (documentation under `src/runtime/reactor/`):
//!
//! - a peer write yields a readable event carrying the registered token, and
//!   nothing is delivered before it (`mod.rs` `Reactor::register`/`poll`);
//! - writable interest on a connected socket yields a writable event;
//! - `modify` switches the interest set: readable-only, writable-only, back;
//! - `deregister` ends delivery for the token and lowers `registration_count`;
//! - a duplicate registration fails with `AlreadyExists`, and `modify` or
//!   `deregister` of an unknown token fails with `NotFound`;
//! - an invalid descriptor is rejected with `InvalidInput` or the platform's
//!   raw `EBADF`, and nothing is registered (`mod.rs:991-993`; the in-crate
//!   epoll suite pins `EBADF`, `epoll_conformance_tests.rs:950-964`);
//! - `poll` with a timeout and nothing ready returns `Ok(0)` within a ceiling
//!   (no lower bound: `Some(d)` blocks *up to* `d`);
//! - `wake()` from another thread ends a `poll(None)`;
//! - a peer close reports hang-up under `Interest::HUP` and read readiness
//!   (end of stream) under `Interest::READABLE`;
//! - 64 ready registrations are each reported exactly once across polls;
//! - concurrent register/deregister while one thread polls keeps
//!   `registration_count` consistent;
//! - `register` completes while another thread is blocked in `poll(None)`;
//! - default (non-edge) registrations are oneshot and re-armed by `modify`;
//! - an accepted `Interest::EDGE_TRIGGERED` registration delivers a new edge
//!   after a full drain without `modify`.
//!
//! `LabReactor` never touches descriptors (`lab.rs:720`): readiness comes from
//! `set_ready`, `inject_event` and `inject_close`, `poll` never blocks
//! (`lab.rs:789-798`), and it keeps no arming state. Its rows cover readiness,
//! interest changes, deregistration, error kinds, timeouts in virtual time,
//! wake, hang-up, batching and concurrent churn; descriptor validity, a
//! blocked `poll(None)`, oneshot re-arming and edge triggering do not apply.
//!
//! Every wait is bounded: readiness is awaited with short `poll` slices up to
//! a two second deadline, and every cross-thread hand-off uses `recv_timeout`.

use super::harness::{
    ConformanceTestResult, RequirementLevel, RuntimeConformanceHarness, TestCategory, TestVerdict,
};
use asupersync::runtime::reactor::{Events, Interest, Reactor, Token};
#[cfg(any(unix, windows))]
use asupersync::runtime::reactor::{Event, LabReactor, Source};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Longest wait for readiness that a contract says must arrive.
const EVENT_DEADLINE: Duration = Duration::from_secs(2);
/// Length of one bounded `poll` call inside a wait loop.
const POLL_SLICE: Duration = Duration::from_millis(50);
/// Window in which a contract says nothing may be delivered.
const QUIET_WINDOW: Duration = Duration::from_millis(150);
/// Generous ceiling on a timed or non-blocking `poll`.
const ELAPSED_CEILING: Duration = Duration::from_secs(5);
/// Overall bound on the multi-threaded churn contract.
const CHURN_DEADLINE: Duration = Duration::from_secs(20);
/// Ready registrations in the batching contract.
const BATCH_SOURCES: usize = 64;
/// First token of the batching contract.
const BATCH_TOKEN_BASE: usize = 1_000;
/// Threads that register and deregister concurrently in the churn contract.
const CHURN_WORKERS: usize = 4;
/// Register/deregister rounds per churn thread.
const CHURN_ROUNDS: usize = 16;
/// Registrations each churn thread keeps until the contract ends.
const CHURN_KEPT: usize = 4;
/// First token of the churn contract.
const CHURN_TOKEN_BASE: usize = 5_000;

/// Tracked io_uring divergences. A row reports one as `ExpectedGap` only when
/// its observation matches the gap exactly and conforms in every other check.
const GAP_REGISTER_WHILE_POLLING: &str = "asupersync-2mc31r: io_uring poll holds the ring lock \
     across submit_and_wait, so register waits for the poll";

/// The tracked gap a backend may show for a contract, if any.
fn known_gap(contract: Contract, kind: RowKind) -> Option<&'static str> {
    match (contract, kind) {
        (Contract::RegisterWhilePollBlocked, RowKind::IoUring) => Some(GAP_REGISTER_WHILE_POLLING),
        _ => None,
    }
}

#[cfg(not(target_os = "linux"))]
const EPOLL_ABSENT: &str = "EpollReactor is compiled only for Linux/Android \
     (src/runtime/reactor/mod.rs:120-121, 148-149); the epoll rows did not run, and \
     this target's own reactor backend is not exercised by this suite";

#[cfg(all(target_os = "linux", not(feature = "io-uring")))]
const IO_URING_ABSENT: &str = "built without the io-uring feature: IoUringReactor is the \
     Unsupported shell (src/runtime/reactor/io_uring.rs:4266-4330), so the io_uring rows \
     and the io_uring_vs_epoll differential did not run";

#[cfg(not(target_os = "linux"))]
const IO_URING_ABSENT: &str = "IoUringReactor is compiled only for Linux/Android \
     (src/runtime/reactor/mod.rs:123-125, 166-167); the io_uring rows did not run";

/// Which backend a row reports on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowKind {
    Epoll,
    IoUring,
    IoUringVsEpoll,
    Lab,
}

macro_rules! reactor_contracts {
    ($(
        $variant:ident {
            slug: $slug:literal,
            level: $level:ident,
            category: $category:ident,
            lab: $lab:literal,
            spec: $spec:literal,
            code: $code:literal $(,)?
        }
    )*) => {
        /// One documented `Reactor` contract.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum Contract {
            $($variant,)*
        }

        impl Contract {
            /// Every contract, in report order.
            const ALL: &'static [Self] = &[$(Self::$variant,)*];

            fn level(self) -> RequirementLevel {
                match self {
                    $(Self::$variant => RequirementLevel::$level,)*
                }
            }

            fn category(self) -> TestCategory {
                match self {
                    $(Self::$variant => TestCategory::$category,)*
                }
            }

            /// Whether `LabReactor` can express the contract at all.
            fn lab_applies(self) -> bool {
                match self {
                    $(Self::$variant => $lab,)*
                }
            }

            /// Where the contract is documented.
            fn spec(self) -> &'static str {
                match self {
                    $(Self::$variant => $spec,)*
                }
            }

            /// Where epoll and io_uring implement it (paths under
            /// `src/runtime/reactor/`), quoted by differential failures.
            fn implementing_code(self) -> &'static str {
                match self {
                    $(Self::$variant => $code,)*
                }
            }

            fn row_name(self, kind: RowKind) -> &'static str {
                match (self, kind) {
                    $(
                        (Self::$variant, RowKind::Epoll) => concat!("epoll/", $slug),
                        (Self::$variant, RowKind::IoUring) => concat!("io_uring/", $slug),
                        (Self::$variant, RowKind::IoUringVsEpoll) => {
                            concat!("io_uring_vs_epoll/", $slug)
                        }
                        (Self::$variant, RowKind::Lab) => concat!("lab/", $slug),
                    )*
                }
            }
        }
    };
}

reactor_contracts! {
    ReadableAfterPeerWrite {
        slug: "readable_after_peer_write",
        level: Must,
        category: IoEventNotification,
        lab: true,
        spec: "src/runtime/reactor/mod.rs:975-1000 (register), 1051-1080 (poll)",
        code: "epoll.rs:325-421 register, 575-610 poll, 277-316 readiness translation; \
               io_uring.rs:1585-1624 register, 1684-1818 poll, 1908-1926 readiness translation",
    }
    WritableOnConnectedSocket {
        slug: "writable_on_connected_socket",
        level: Must,
        category: IoEventNotification,
        lab: true,
        spec: "src/runtime/reactor/mod.rs:903-907 (writable readiness), 1051-1080 (poll)",
        code: "epoll.rs:227-247 interest to EPOLLOUT, 277-308 translation; \
               io_uring.rs:1883-1906 interest to POLLOUT, 1908-1926 translation",
    }
    ModifySwitchesInterest {
        slug: "modify_switches_interest",
        level: Must,
        category: RegistrationLifecycle,
        lab: true,
        spec: "src/runtime/reactor/mod.rs:1002-1024 (modify)",
        code: "epoll.rs:423-500 modify, 277-308 readiness masked by interest; \
               io_uring.rs:1626-1670 modify, 1883-1906 poll mask from interest",
    }
    DeregisterStopsEvents {
        slug: "deregister_stops_events",
        level: Must,
        category: RegistrationLifecycle,
        lab: true,
        spec: "src/runtime/reactor/mod.rs:1026-1049 (deregister), 1108-1111 (registration_count)",
        code: "epoll.rs:502-573 deregister, 311-316 unknown tokens dropped; \
               io_uring.rs:1672-1682 deregister, 1958-1969 stale completions dropped",
    }
    RegistrationErrors {
        slug: "registration_errors",
        level: Must,
        category: RegistrationLifecycle,
        lab: true,
        spec: "src/runtime/reactor/mod.rs:987-993 (AlreadyExists), 1012-1017 and 1038-1042 (NotFound)",
        code: "epoll.rs:344-358, 435-443, 504-523; io_uring.rs:1593-1604, 1628-1631, 1674-1676",
    }
    InvalidDescriptorRejected {
        slug: "invalid_descriptor_rejected",
        level: Should,
        category: RegistrationLifecycle,
        lab: false,
        spec: "src/runtime/reactor/mod.rs:991-993 (InvalidInput, or platform errors such as \
               EBADF); epoll_conformance_tests.rs:950-964 pins EBADF",
        code: "epoll.rs:335-337 (-1 returns raw EBADF), 340-342 (fstat failure returns InvalidInput); \
               io_uring.rs:1608 calls 846-850 (fcntl failure returns raw EBADF)",
    }
    PollTimeoutReturnsZero {
        slug: "poll_timeout_returns_zero",
        level: Must,
        category: IoEventNotification,
        lab: true,
        spec: "src/runtime/reactor/mod.rs:1059-1067 (timeout semantics, Ok(0) on timeout)",
        code: "epoll.rs:575-610 (Poller::wait); io_uring.rs:1699-1719 (ETIME treated as timeout)",
    }
    WakeEndsBlockingPoll {
        slug: "wake_ends_blocking_poll",
        level: Must,
        category: ThreadSafety,
        lab: true,
        spec: "src/runtime/reactor/mod.rs:1082-1106 (wake), 1060 (None blocks)",
        code: "epoll.rs:612-615 (Poller::notify); io_uring.rs:1820-1838 wake, 1738-1771 wake completion",
    }
    PeerCloseReportsHangup {
        slug: "peer_close_reports_hangup",
        level: Must,
        category: IoEventNotification,
        lab: true,
        spec: "src/runtime/reactor/interest.rs:58-59 (HUP: peer closed); mod.rs:903-907 (readable)",
        code: "epoll.rs:277-308 (EPOLLHUP folded into read readiness and HUP); \
               io_uring.rs:1883-1926 (POLLRDHUP and POLLHUP to HUP)",
    }
    BatchDeliversEachTokenOnce {
        slug: "batch_delivers_each_token_once",
        level: Must,
        category: IoEventNotification,
        lab: true,
        spec: "src/runtime/reactor/mod.rs:272-305 (Events), 1064-1067 (poll count), 930-933 (oneshot)",
        code: "epoll.rs:575-610 (batch bounded by Events capacity); \
               io_uring.rs:1721-1724 and 1949-1999 (whole completion queue drained per poll)",
    }
    ConcurrentRegistrationChurn {
        slug: "concurrent_registration_churn",
        level: Must,
        category: ThreadSafety,
        lab: true,
        spec: "src/runtime/reactor/mod.rs:918-922 (thread safety), 1108-1111 (registration_count)",
        code: "epoll.rs:171-180 (state mutex, atomic count); \
               io_uring.rs:1143-1163 (ring and state mutexes), 1840-1842",
    }
    RegisterWhilePollBlocked {
        slug: "register_while_poll_blocked",
        level: Should,
        category: ThreadSafety,
        lab: false,
        spec: "src/runtime/reactor/mod.rs:918-922 (all methods callable concurrently)",
        code: "epoll.rs:575-594 (the wait holds only the event-buffer lock) and 345 (register \
               takes the state lock); io_uring.rs:1697-1701 (ring lock held across \
               submit_and_wait) and 1343-1350 (register needs the ring lock); callers work \
               around it in src/runtime/io_driver.rs:626-630 (wake before register)",
    }
    OneshotDefaultRequiresRearm {
        slug: "oneshot_default_requires_rearm",
        level: Must,
        category: EdgeTriggeredMode,
        lab: false,
        spec: "src/runtime/reactor/mod.rs:930-933 and 93-97 (Unix backends default to oneshot, re-armed by modify)",
        code: "epoll.rs:251-263 (non-edge maps to PollMode::Oneshot); \
               io_uring.rs:1970-1972 (a completion disarms), 1653-1658 (modify re-arms)",
    }
    EdgeTriggeredRedeliversAfterDrain {
        slug: "edge_triggered_redelivers_after_drain",
        level: Should,
        category: EdgeTriggeredMode,
        lab: false,
        spec: "src/runtime/reactor/mod.rs:935-937 and 99-101; interest.rs:68-70 (EDGE_TRIGGERED)",
        code: "epoll.rs:252-257 (EDGE_TRIGGERED maps to PollMode::Edge); io_uring.rs:1866-1870 \
               (a persistent edge interest is one multishot PollAdd) and 1902-1904 (EPOLLET), \
               1957-1972 (a completion with IORING_CQE_F_MORE leaves it armed), 4227-4259 \
               (a multishot poll the kernel ended is re-armed)",
    }
}

/// What one contract run saw on one backend.
#[derive(Debug, Default)]
struct Observation {
    /// Contract violations; any entry fails the row.
    violations: Vec<String>,
    /// Backend-neutral record of the observable outcome, compared by the
    /// differential rows. Entries never contain timings or descriptor numbers.
    trace: Vec<String>,
    /// Set when the backend declined an optional mode the documentation lets
    /// it decline; the row is then skipped rather than passed.
    declined: Option<String>,
    /// The tracked gap this observation matched, if it matched one.
    gap: Option<&'static str>,
    /// Indices of the `trace` entries that the matched gap explains.
    gap_lines: Vec<usize>,
    /// Remarks that are reported but never compared, such as a tracked gap
    /// that no longer reproduces.
    remarks: Vec<String>,
}

impl Observation {
    fn note(&mut self, entry: impl Into<String>) {
        self.trace.push(entry.into());
    }

    /// Records a trace entry that deviates from the contract exactly as the
    /// tracked `gap` describes.
    fn gap_note(&mut self, gap: &'static str, entry: impl Into<String>) {
        self.gap_lines.push(self.trace.len());
        self.trace.push(entry.into());
        self.gap = Some(gap);
    }

    /// Notes that a tracked gap did not reproduce in this run.
    fn gap_closed_remark(&mut self, gap: Option<&'static str>, evidence: &str) {
        if let Some(gap) = gap {
            if self.gap.is_none() && self.violations.is_empty() {
                self.remarks
                    .push(format!("known gap appears closed ({evidence}): {gap}"));
            }
        }
    }

    fn violation(&mut self, message: impl Into<String>) {
        let message = message.into();
        if !self.violations.contains(&message) {
            self.violations.push(message);
        }
    }

    fn require(&mut self, holds: bool, message: impl FnOnce() -> String) {
        if !holds {
            self.violation(message());
        }
    }

    fn verdict(&self) -> TestVerdict {
        if !self.violations.is_empty() {
            TestVerdict::Fail(self.violations.join("; "))
        } else if let Some(gap) = self.gap {
            TestVerdict::ExpectedGap(gap.to_owned())
        } else if let Some(reason) = &self.declined {
            TestVerdict::Skip(reason.clone())
        } else {
            TestVerdict::Pass
        }
    }
}

/// Runs one contract body; an operation error becomes a violation.
fn observe(body: impl FnOnce(&mut Observation) -> io::Result<()>) -> Observation {
    let mut observation = Observation::default();
    if let Err(err) = body(&mut observation) {
        observation.violation(format!("operation failed: {err}"));
        observation.note(format!("aborted: {err}"));
    }
    observation
}

/// Labels an operation error with the step that produced it.
fn during(step: &'static str) -> impl FnOnce(io::Error) -> io::Error {
    move |err| io::Error::new(err.kind(), format!("{step}: {}", describe_error(&err)))
}

fn describe_error(err: &io::Error) -> String {
    match err.raw_os_error() {
        Some(code) => format!("{:?} (os error {code})", err.kind()),
        None => format!("{:?}", err.kind()),
    }
}

fn describe_outcome(outcome: &io::Result<()>) -> String {
    match outcome {
        Ok(()) => "Ok".to_owned(),
        Err(err) => format!("Err({})", describe_error(err)),
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

/// Readiness flags as a compact, stable string such as `R+H`.
fn flags(ready: Interest) -> String {
    let named = [
        (Interest::READABLE, "R"),
        (Interest::WRITABLE, "W"),
        (Interest::ERROR, "E"),
        (Interest::HUP, "H"),
        (Interest::PRIORITY, "P"),
    ];
    let parts: Vec<&str> = named
        .iter()
        .filter(|(flag, _)| ready.contains(*flag))
        .map(|(_, name)| *name)
        .collect();
    if parts.is_empty() {
        "none".to_owned()
    } else {
        parts.join("+")
    }
}

fn list(seen: &[(Token, Interest)]) -> String {
    if seen.is_empty() {
        return "none".to_owned();
    }
    seen.iter()
        .map(|(token, ready)| format!("{}:{}", token.0, flags(*ready)))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Union of every readiness reported for `token`, if any was.
fn readiness_of(seen: &[(Token, Interest)], token: Token) -> Option<Interest> {
    seen.iter()
        .filter(|(seen_token, _)| *seen_token == token)
        .map(|(_, ready)| *ready)
        .reduce(|left, right| left | right)
}

/// Every event must carry a token this contract registered.
fn expect_only(obs: &mut Observation, seen: &[(Token, Interest)], registered: &[Token]) {
    for (token, ready) in seen {
        if !registered.contains(token) {
            obs.violation(format!(
                "event for token {} that this contract never registered ({})",
                token.0,
                flags(*ready)
            ));
        }
    }
}

/// Records the readiness delivered for `token`, or a violation when none was.
fn delivered(
    obs: &mut Observation,
    label: &str,
    seen: &[(Token, Interest)],
    token: Token,
) -> Option<Interest> {
    let ready = readiness_of(seen, token);
    match ready {
        Some(ready) => obs.note(format!("{label}: {}", flags(ready))),
        None => {
            obs.note(format!("{label}: none"));
            obs.violation(format!(
                "{label}: no event for token {} within the wait",
                token.0
            ));
        }
    }
    ready
}

/// The token's event must carry read readiness.
fn expect_readable(
    obs: &mut Observation,
    label: &str,
    seen: &[(Token, Interest)],
    token: Token,
) -> bool {
    expect_only(obs, seen, &[token]);
    match delivered(obs, label, seen, token) {
        Some(ready) => {
            obs.require(ready.is_readable(), || {
                format!("{label}: event lacks read readiness ({})", flags(ready))
            });
            ready.is_readable()
        }
        None => false,
    }
}

/// The token's event must carry exactly the one direction its interest names.
fn expect_direction(
    obs: &mut Observation,
    label: &str,
    seen: &[(Token, Interest)],
    token: Token,
    readable: bool,
) {
    expect_only(obs, seen, &[token]);
    if let Some(ready) = delivered(obs, label, seen, token) {
        let (wanted, unwanted) = if readable {
            (ready.is_readable(), ready.is_writable())
        } else {
            (ready.is_writable(), ready.is_readable())
        };
        obs.require(wanted && !unwanted, || {
            format!(
                "{label}: readiness {} does not match the interest set",
                flags(ready)
            )
        });
    }
}

/// Records an outcome that the documentation says must be `Err(kind)`.
fn expect_error(obs: &mut Observation, label: &str, outcome: io::Result<()>, kind: io::ErrorKind) {
    if matches!(&outcome, Err(err) if err.kind() == kind) {
        // Only the documented kind is recorded, so backends that differ only
        // in errno do not diverge.
        obs.note(format!("{label}: Err({kind:?})"));
    } else {
        obs.note(format!("{label}: {}", describe_outcome(&outcome)));
        obs.violation(format!(
            "{label}: expected Err({kind:?}), got {}",
            describe_outcome(&outcome)
        ));
    }
}

/// One `poll` call, retried on `Interrupted` (a documented, benign error),
/// checking that the returned count equals the events stored.
fn poll_once(
    reactor: &dyn Reactor,
    events: &mut Events,
    timeout: Option<Duration>,
    obs: &mut Observation,
) -> io::Result<Vec<(Token, Interest)>> {
    let mut interrupted = 0;
    loop {
        match reactor.poll(events, timeout) {
            Ok(count) => {
                let stored = events.len();
                obs.require(count == stored, || {
                    format!("poll returned {count} but stored {stored} events (mod.rs:1064-1067)")
                });
                return Ok(events
                    .iter()
                    .map(|event| (event.token, event.ready))
                    .collect());
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted && interrupted < 8 => {
                interrupted += 1;
            }
            Err(err) => return Err(during("poll")(err)),
        }
    }
}

/// Counts how often each source of a batch was reported.
struct Tally {
    base: usize,
    deliveries: Vec<usize>,
    foreign: usize,
    unreadable: usize,
}

impl Tally {
    fn new(base: usize, sources: usize) -> Self {
        Self {
            base,
            deliveries: vec![0; sources],
            foreign: 0,
            unreadable: 0,
        }
    }

    fn record(&mut self, token: Token, ready: Interest) {
        let slot = token
            .0
            .checked_sub(self.base)
            .filter(|offset| *offset < self.deliveries.len());
        match slot {
            Some(offset) => {
                self.deliveries[offset] += 1;
                if !ready.is_readable() {
                    self.unreadable += 1;
                }
            }
            None => self.foreign += 1,
        }
    }

    fn complete(&self) -> bool {
        self.deliveries.iter().all(|&count| count > 0)
    }

    fn judge(&self, obs: &mut Observation) {
        let total = self.deliveries.len();
        let missing = self.deliveries.iter().filter(|&&count| count == 0).count();
        let repeated = self.deliveries.iter().filter(|&&count| count > 1).count();
        obs.require(missing == 0, || {
            format!("{missing} of {total} ready sources were never reported")
        });
        obs.require(repeated == 0, || {
            format!("{repeated} of {total} sources were reported more than once")
        });
        obs.require(self.foreign == 0, || {
            format!("{} events carried tokens outside the batch", self.foreign)
        });
        obs.require(self.unreadable == 0, || {
            format!("{} batch events lacked read readiness", self.unreadable)
        });
        obs.note(format!(
            "{} of {total} sources reported, {repeated} repeated, {} foreign, {} unreadable",
            total - missing,
            self.foreign,
            self.unreadable
        ));
    }
}

/// Joins threads that already reported, giving each until `deadline` to exit.
fn join_within<T>(
    obs: &mut Observation,
    handles: Vec<thread::JoinHandle<T>>,
    what: &str,
    deadline: Duration,
) -> Vec<T> {
    let end = Instant::now() + deadline;
    let mut joined = Vec::with_capacity(handles.len());
    for handle in handles {
        // The thread has sent its last message; this only waits out its exit.
        while !handle.is_finished() && Instant::now() < end {
            thread::yield_now();
        }
        if handle.is_finished() {
            match handle.join() {
                Ok(value) => joined.push(value),
                Err(_) => obs.violation(format!("{what} panicked")),
            }
        } else {
            obs.violation(format!(
                "{what} was still running {deadline:?} after its contract ended; left detached"
            ));
        }
    }
    joined
}

fn churn_first_token(worker: usize) -> usize {
    CHURN_TOKEN_BASE + worker * (CHURN_KEPT + CHURN_ROUNDS)
}

fn churn_failure(worker: usize, step: &str, err: &io::Error) -> String {
    format!("churn worker {worker}: {step}: {err}")
}

#[derive(Debug, Default)]
struct ChurnPollerReport {
    foreign: usize,
    errors: Vec<String>,
    peak_registrations: usize,
}

/// Polls in 20 ms slices until `stop`, sampling `registration_count` each turn.
fn spawn_churn_poller(
    reactor: &Arc<dyn Reactor>,
    stop: &Arc<AtomicBool>,
) -> io::Result<(thread::JoinHandle<()>, mpsc::Receiver<ChurnPollerReport>)> {
    let reactor = Arc::clone(reactor);
    let stop = Arc::clone(stop);
    let tokens = CHURN_TOKEN_BASE..churn_first_token(CHURN_WORKERS);
    let (report_tx, report_rx) = mpsc::channel();
    let handle = thread::Builder::new()
        .name("reactor-churn-poller".to_owned())
        .spawn(move || {
            let poller: &dyn Reactor = &*reactor;
            let mut report = ChurnPollerReport::default();
            let mut events = Events::with_capacity(32);
            while !stop.load(Ordering::Acquire) {
                match poller.poll(&mut events, Some(Duration::from_millis(20))) {
                    Ok(_) => {
                        for event in &events {
                            if !tokens.contains(&event.token.0) {
                                report.foreign += 1;
                            }
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                    Err(err) => {
                        if report.errors.len() < 4 {
                            report.errors.push(describe_error(&err));
                        }
                    }
                }
                report.peak_registrations =
                    report.peak_registrations.max(poller.registration_count());
                thread::yield_now();
            }
            let _ = report_tx.send(report);
        })
        .map_err(during("spawn churn poller"))?;
    Ok((handle, report_rx))
}

/// Collects the churn poller's report; true once the poller thread has exited.
fn finish_churn_poller(
    obs: &mut Observation,
    handle: thread::JoinHandle<()>,
    reports: &mpsc::Receiver<ChurnPollerReport>,
) -> bool {
    let peak_bound = CHURN_WORKERS * (CHURN_KEPT + 1);
    match reports.recv_timeout(EVENT_DEADLINE) {
        Ok(report) => {
            obs.require(report.errors.is_empty(), || {
                format!("poll failed during churn: {}", report.errors.join(", "))
            });
            obs.require(report.foreign == 0, || {
                format!(
                    "{} events carried tokens no churn thread registered",
                    report.foreign
                )
            });
            obs.require(report.peak_registrations <= peak_bound, || {
                format!(
                    "registration_count peaked at {}, above the {peak_bound} registrations \
                     that can be live at once",
                    report.peak_registrations
                )
            });
            obs.note(format!(
                "poller errors: {}; foreign tokens: {}; peak count within bound: {}",
                report.errors.len(),
                report.foreign,
                yes_no(report.peak_registrations <= peak_bound)
            ));
        }
        Err(_) => {
            obs.violation("the churn poller did not stop within the deadline");
            obs.note("churn poller: did not stop");
        }
    }
    !join_within(obs, vec![handle], "churn poller", EVENT_DEADLINE).is_empty()
}

/// Several threads register and deregister while one thread polls.
///
/// Each worker keeps `CHURN_KEPT` registrations and cycles `CHURN_ROUNDS`
/// more; at most `CHURN_KEPT + 1` of its registrations are live at once, which
/// bounds every `registration_count` sample the poller takes.
fn churn_contract<T, W>(
    reactor: &Arc<dyn Reactor>,
    obs: &mut Observation,
    worker: W,
    token_of: fn(&T) -> Token,
) -> io::Result<()>
where
    T: Send + 'static,
    W: Fn(usize) -> Result<Vec<T>, String> + Send + Sync + 'static,
{
    let r: &dyn Reactor = &**reactor;
    let stop = Arc::new(AtomicBool::new(false));
    let (poller, poller_reports) = spawn_churn_poller(reactor, &stop)?;
    let worker = Arc::new(worker);
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let mut handles = Vec::with_capacity(CHURN_WORKERS);
    for index in 0..CHURN_WORKERS {
        let worker = Arc::clone(&worker);
        let done = done_tx.clone();
        let spawned = thread::Builder::new()
            .name(format!("reactor-churn-{index}"))
            .spawn(move || {
                let outcome = worker(index);
                let _ = done.send(());
                outcome
            });
        match spawned {
            Ok(handle) => handles.push(handle),
            Err(err) => obs.violation(format!("spawn churn worker {index}: {err}")),
        }
    }
    drop(done_tx);

    let end = Instant::now() + CHURN_DEADLINE;
    let mut finished = 0;
    while finished < handles.len() {
        let remaining = end.saturating_duration_since(Instant::now());
        match done_rx.recv_timeout(remaining) {
            Ok(()) => finished += 1,
            Err(_) => break,
        }
    }
    obs.require(finished == CHURN_WORKERS, || {
        format!("{finished} of {CHURN_WORKERS} churn workers finished within {CHURN_DEADLINE:?}")
    });

    let mut kept = Vec::new();
    let mut failed_workers = 0;
    let outcomes = join_within(obs, handles, "churn worker", EVENT_DEADLINE);
    let workers_exited = outcomes.len() == CHURN_WORKERS;
    for outcome in outcomes {
        match outcome {
            Ok(mut records) => kept.append(&mut records),
            Err(message) => {
                failed_workers += 1;
                obs.violation(message);
            }
        }
    }
    let expected = CHURN_WORKERS * CHURN_KEPT;
    if workers_exited {
        let count = r.registration_count();
        obs.require(kept.len() == expected && count == expected, || {
            format!(
                "after churn: {} kept registrations and registration_count {count}, \
                 expected {expected}",
                kept.len()
            )
        });
        obs.note(format!(
            "failed workers: {failed_workers}; registration_count after churn: {count}"
        ));
    } else {
        obs.note("registration_count after churn: not sampled, a worker is still running");
    }

    stop.store(true, Ordering::Release);
    // Ends a poll that is still waiting out its slice.
    let _ = r.wake();
    let poller_exited = finish_churn_poller(obs, poller, &poller_reports);
    if !(workers_exited && poller_exited) {
        // A thread that never returned may still hold backend locks, so no
        // further call goes through the reactor; the descriptors stay open
        // for registrations that may still be live.
        obs.note("cleanup skipped: a churn thread is still running");
        std::mem::forget(kept);
        return Ok(());
    }

    for record in &kept {
        r.deregister(token_of(record))
            .map_err(during("deregister kept registration"))?;
    }
    let remaining = r.registration_count();
    obs.require(remaining == 0, || {
        format!("registration_count is {remaining} after every registration was removed")
    });
    obs.note(format!("registration_count after cleanup: {remaining}"));
    // Descriptors close only after their registrations are gone.
    drop(kept);
    Ok(())
}

/// Verdict of an `io_uring_vs_epoll` row.
///
/// Pass when io_uring observed exactly what epoll observed. ExpectedGap only
/// when io_uring's own observation matched the contract's tracked gap with no
/// other violation, and every trace line that differs from epoll's is a line
/// that gap explains. Anything else fails, naming both behaviours.
fn differential_verdict(
    contract: Contract,
    epoll: Option<&Observation>,
    uring: &Observation,
) -> TestVerdict {
    let Some(epoll) = epoll else {
        return TestVerdict::Fail(format!(
            "no epoll observation to compare against {}",
            contract.row_name(RowKind::IoUring)
        ));
    };
    if epoll.trace == uring.trace {
        return TestVerdict::Pass;
    }
    if let Some(gap) = uring.gap {
        let explained = known_gap(contract, RowKind::IoUring) == Some(gap)
            && uring.violations.is_empty()
            && epoll.trace.len() == uring.trace.len()
            && epoll
                .trace
                .iter()
                .zip(&uring.trace)
                .enumerate()
                .all(|(line, (seen_by_epoll, seen_by_uring))| {
                    seen_by_epoll == seen_by_uring || uring.gap_lines.contains(&line)
                });
        if explained {
            return TestVerdict::ExpectedGap(gap.to_owned());
        }
    }
    TestVerdict::Fail(format!(
        "backends diverge: epoll observed [{}]; io_uring observed [{}]; implementing code: {}",
        epoll.trace.join(" | "),
        uring.trace.join(" | "),
        contract.implementing_code()
    ))
}

/// A single row for a backend that is absent from this build or host.
fn unavailable(name: &'static str, reason: impl Into<String>) -> ConformanceTestResult {
    ConformanceTestResult {
        test_name: name,
        requirement_level: RequirementLevel::May,
        category: TestCategory::PlatformAbstraction,
        verdict: TestVerdict::Skip(reason.into()),
        spec_section: Some("src/runtime/reactor/mod.rs:48-63 (public export contract)"),
        duration_micros: None,
    }
}

/// Conformance harness that runs every reactor contract against the
/// production reactors available in this build.
pub struct ReactorConformanceHarness {
    harness: RuntimeConformanceHarness,
}

impl ReactorConformanceHarness {
    /// Create a new reactor conformance test harness.
    pub fn new() -> Self {
        Self {
            harness: RuntimeConformanceHarness::new(),
        }
    }

    /// Run the complete reactor conformance suite: the epoll rows, the
    /// io_uring rows with their differential against epoll, and the lab rows.
    pub fn run_full_suite(&mut self) -> Vec<ConformanceTestResult> {
        let (mut results, epoll_observations) = self.epoll_rows();
        results.extend(self.io_uring_rows(&epoll_observations));
        results.extend(self.lab_rows());
        results
    }

    /// The epoll rows, plus each contract's observation for the differential.
    fn epoll_rows(&self) -> (Vec<ConformanceTestResult>, Vec<(Contract, Observation)>) {
        #[cfg(target_os = "linux")]
        {
            self.kernel_rows(RowKind::Epoll, kernel_checks::epoll)
        }
        #[cfg(not(target_os = "linux"))]
        {
            (
                vec![unavailable("epoll/backend_available", EPOLL_ABSENT)],
                Vec::new(),
            )
        }
    }

    /// The io_uring rows and one differential row per contract, or a single
    /// skipped availability row.
    fn io_uring_rows(&self, epoll: &[(Contract, Observation)]) -> Vec<ConformanceTestResult> {
        #[cfg(all(target_os = "linux", feature = "io-uring"))]
        {
            if let Err(err) = kernel_checks::io_uring() {
                return vec![unavailable(
                    "io_uring/backend_available",
                    format!(
                        "IoUringReactor::new() failed on this host ({err}); the io_uring rows \
                         and the io_uring_vs_epoll differential did not run"
                    ),
                )];
            }
            let (mut rows, observations) =
                self.kernel_rows(RowKind::IoUring, kernel_checks::io_uring);
            for (contract, uring) in &observations {
                let reference = epoll
                    .iter()
                    .find(|(epoll_contract, _)| epoll_contract == contract)
                    .map(|(_, observation)| observation);
                rows.push(self.differential_row(*contract, reference, uring));
            }
            rows
        }
        #[cfg(not(all(target_os = "linux", feature = "io-uring")))]
        {
            let _ = epoll;
            vec![unavailable("io_uring/backend_available", IO_URING_ABSENT)]
        }
    }

    /// One row per contract against a fresh reactor from `make`.
    #[cfg(target_os = "linux")]
    fn kernel_rows(
        &self,
        kind: RowKind,
        make: fn() -> io::Result<Arc<dyn Reactor>>,
    ) -> (Vec<ConformanceTestResult>, Vec<(Contract, Observation)>) {
        let mut rows = Vec::with_capacity(Contract::ALL.len());
        let mut observations = Vec::with_capacity(Contract::ALL.len());
        for &contract in Contract::ALL {
            let mut kept = None;
            let row = self
                .harness
                .run_test(
                    || {
                        let observation = match make() {
                            Ok(reactor) => kernel_checks::run(contract, kind, &reactor),
                            Err(err) => {
                                let mut failed = Observation::default();
                                failed.violation(format!("reactor construction failed: {err}"));
                                failed.note(format!(
                                    "construction failed: {}",
                                    describe_error(&err)
                                ));
                                failed
                            }
                        };
                        // Remarks never change a verdict; they surface in the
                        // test output so a closed gap gets noticed.
                        for remark in &observation.remarks {
                            eprintln!("{}: {remark}", contract.row_name(kind));
                        }
                        let verdict = observation.verdict();
                        kept = Some(observation);
                        verdict
                    },
                    contract.row_name(kind),
                    contract.level(),
                    contract.category(),
                )
                .with_spec_section(contract.spec());
            rows.push(row);
            observations.push((contract, kept.unwrap_or_default()));
        }
        (rows, observations)
    }

    /// Compares io_uring's observable outcome with epoll's.
    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    fn differential_row(
        &self,
        contract: Contract,
        epoll: Option<&Observation>,
        uring: &Observation,
    ) -> ConformanceTestResult {
        self.harness
            .run_test(
                || differential_verdict(contract, epoll, uring),
                contract.row_name(RowKind::IoUringVsEpoll),
                contract.level(),
                contract.category(),
            )
            .with_spec_section(contract.spec())
    }

    /// One row per contract `LabReactor` can express.
    fn lab_rows(&self) -> Vec<ConformanceTestResult> {
        #[cfg(any(unix, windows))]
        {
            Contract::ALL
                .iter()
                .copied()
                .filter(|contract| contract.lab_applies())
                .map(|contract| {
                    self.harness
                        .run_test(
                            || lab_checks::run(contract).verdict(),
                            contract.row_name(RowKind::Lab),
                            contract.level(),
                            contract.category(),
                        )
                        .with_spec_section(contract.spec())
                })
                .collect()
        }
        #[cfg(not(any(unix, windows)))]
        {
            vec![unavailable(
                "lab/backend_available",
                "this target defines no reactor Source, so LabReactor registrations cannot be named",
            )]
        }
    }
}

impl Default for ReactorConformanceHarness {
    fn default() -> Self {
        Self::new()
    }
}

/// Contracts run on kernel descriptors against `EpollReactor` and `IoUringReactor`.
#[cfg(target_os = "linux")]
mod kernel_checks {
    use super::*;
    use asupersync::runtime::reactor::EpollReactor;
    #[cfg(feature = "io-uring")]
    use asupersync::runtime::reactor::IoUringReactor;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::net::UnixStream;

    pub(super) fn epoll() -> io::Result<Arc<dyn Reactor>> {
        let reactor: Arc<dyn Reactor> = Arc::new(EpollReactor::new()?);
        Ok(reactor)
    }

    #[cfg(feature = "io-uring")]
    pub(super) fn io_uring() -> io::Result<Arc<dyn Reactor>> {
        let reactor: Arc<dyn Reactor> = Arc::new(IoUringReactor::new()?);
        Ok(reactor)
    }

    pub(super) fn run(contract: Contract, kind: RowKind, reactor: &Arc<dyn Reactor>) -> Observation {
        // Only the tracked io_uring gap can turn a deviation into an
        // ExpectedGap; on every other row and backend `gap` is None.
        let gap = known_gap(contract, kind);
        observe(|obs| match contract {
            Contract::ReadableAfterPeerWrite => readable_after_peer_write(reactor, obs),
            Contract::WritableOnConnectedSocket => writable_on_connected_socket(reactor, obs),
            Contract::ModifySwitchesInterest => modify_switches_interest(reactor, obs),
            Contract::DeregisterStopsEvents => deregister_stops_events(reactor, obs),
            Contract::RegistrationErrors => registration_errors(reactor, obs),
            Contract::InvalidDescriptorRejected => invalid_descriptor_rejected(reactor, obs),
            Contract::PollTimeoutReturnsZero => poll_timeout_returns_zero(reactor, obs),
            Contract::WakeEndsBlockingPoll => wake_ends_blocking_poll(reactor, obs),
            Contract::PeerCloseReportsHangup => peer_close_reports_hangup(reactor, obs),
            Contract::BatchDeliversEachTokenOnce => batch_delivers_each_token_once(reactor, obs),
            Contract::ConcurrentRegistrationChurn => concurrent_registration_churn(reactor, obs),
            Contract::RegisterWhilePollBlocked => register_while_poll_blocked(reactor, gap, obs),
            Contract::OneshotDefaultRequiresRearm => oneshot_default_requires_rearm(reactor, obs),
            Contract::EdgeTriggeredRedeliversAfterDrain => {
                edge_triggered_redelivers_after_drain(reactor, obs)
            }
        })
    }

    /// A descriptor number with no owned resource behind it.
    struct DescriptorNumber(RawFd);

    impl AsRawFd for DescriptorNumber {
        fn as_raw_fd(&self) -> RawFd {
            self.0
        }
    }

    /// A connected, nonblocking pair: `.0` is registered, `.1` is the peer.
    fn connected_pair() -> io::Result<(UnixStream, UnixStream)> {
        let (local, peer) = UnixStream::pair().map_err(during("UnixStream::pair"))?;
        local
            .set_nonblocking(true)
            .map_err(during("set_nonblocking"))?;
        peer.set_nonblocking(true)
            .map_err(during("set_nonblocking"))?;
        Ok((local, peer))
    }

    fn send(peer: &UnixStream, bytes: &[u8]) -> io::Result<()> {
        let mut writer = peer;
        writer.write_all(bytes).map_err(during("peer write"))
    }

    /// Reads until the socket would block or reports end of stream.
    fn drain(local: &UnixStream) -> io::Result<usize> {
        let mut reader = local;
        let mut buffer = [0_u8; 256];
        let mut total = 0;
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => return Ok(total),
                Ok(read) => total += read,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(total),
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err(during("drain read")(err)),
            }
        }
    }

    /// Polls in bounded slices until `done` holds or `window` elapses.
    fn poll_for(
        r: &dyn Reactor,
        window: Duration,
        obs: &mut Observation,
        mut done: impl FnMut(&[(Token, Interest)]) -> bool,
    ) -> io::Result<Vec<(Token, Interest)>> {
        let end = Instant::now() + window;
        let mut events = Events::with_capacity(64);
        let mut seen = Vec::new();
        loop {
            let remaining = end.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(seen);
            }
            seen.extend(poll_once(
                r,
                &mut events,
                Some(remaining.min(POLL_SLICE)),
                obs,
            )?);
            if done(&seen) {
                return Ok(seen);
            }
        }
    }

    /// Everything delivered until `token` shows up or the event deadline passes.
    fn wait_for(
        r: &dyn Reactor,
        token: Token,
        obs: &mut Observation,
    ) -> io::Result<Vec<(Token, Interest)>> {
        poll_for(r, EVENT_DEADLINE, obs, |seen| {
            seen.iter().any(|(seen_token, _)| *seen_token == token)
        })
    }

    /// Everything delivered during a window in which nothing may be.
    fn quiet(r: &dyn Reactor, obs: &mut Observation) -> io::Result<Vec<(Token, Interest)>> {
        poll_for(r, QUIET_WINDOW, obs, |_| false)
    }

    enum PollerMessage {
        Entering,
        Returned(io::Result<Vec<(Token, Interest)>>),
    }

    fn describe_message(message: &PollerMessage) -> String {
        match message {
            PollerMessage::Entering => "entering".to_owned(),
            PollerMessage::Returned(Ok(seen)) => format!("Ok, events: {}", list(seen)),
            PollerMessage::Returned(Err(err)) => format!("Err({})", describe_error(err)),
        }
    }

    /// Starts a thread that runs exactly one `poll(None)` and reports back.
    fn spawn_blocking_poll(
        reactor: &Arc<dyn Reactor>,
        name: &str,
    ) -> io::Result<(thread::JoinHandle<()>, mpsc::Receiver<PollerMessage>)> {
        let reactor = Arc::clone(reactor);
        let (tx, rx) = mpsc::channel();
        let handle = thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                let poller: &dyn Reactor = &*reactor;
                let mut events = Events::with_capacity(16);
                let _ = tx.send(PollerMessage::Entering);
                let outcome = poller
                    .poll(&mut events, None)
                    .map(|_| events.iter().map(|event| (event.token, event.ready)).collect());
                let _ = tx.send(PollerMessage::Returned(outcome));
            })
            .map_err(during("spawn poll(None) thread"))?;
        Ok((handle, rx))
    }

    fn await_entering(obs: &mut Observation, from_poller: &mpsc::Receiver<PollerMessage>) -> bool {
        match from_poller.recv_timeout(EVENT_DEADLINE) {
            Ok(PollerMessage::Entering) => true,
            Ok(message) => {
                obs.violation(format!(
                    "the poll(None) thread reported before entering: {}",
                    describe_message(&message)
                ));
                false
            }
            Err(_) => {
                obs.violation("the poll(None) thread did not start within the deadline");
                false
            }
        }
    }

    fn readable_after_peer_write(
        reactor: &Arc<dyn Reactor>,
        obs: &mut Observation,
    ) -> io::Result<()> {
        let r: &dyn Reactor = &**reactor;
        let (local, peer) = connected_pair()?;
        let token = Token::new(101);
        r.register(&local, token, Interest::READABLE)
            .map_err(during("register"))?;
        let count = r.registration_count();
        obs.require(count == 1, || {
            format!("registration_count is {count} after one register")
        });
        let before = quiet(r, obs)?;
        obs.require(before.is_empty(), || {
            format!("events before any peer write: {}", list(&before))
        });
        obs.note(format!("before the peer write: {}", list(&before)));
        send(&peer, b"x")?;
        let seen = wait_for(r, token, obs)?;
        expect_readable(obs, "after the peer write", &seen, token);
        r.deregister(token).map_err(during("deregister"))?;
        Ok(())
    }

    fn writable_on_connected_socket(
        reactor: &Arc<dyn Reactor>,
        obs: &mut Observation,
    ) -> io::Result<()> {
        let r: &dyn Reactor = &**reactor;
        let (local, _peer) = connected_pair()?;
        let token = Token::new(102);
        r.register(&local, token, Interest::WRITABLE)
            .map_err(during("register"))?;
        let seen = wait_for(r, token, obs)?;
        expect_only(obs, &seen, &[token]);
        if let Some(ready) = delivered(obs, "connected socket", &seen, token) {
            obs.require(ready.is_writable(), || {
                format!("event lacks write readiness ({})", flags(ready))
            });
        }
        r.deregister(token).map_err(during("deregister"))?;
        Ok(())
    }

    fn modify_switches_interest(
        reactor: &Arc<dyn Reactor>,
        obs: &mut Observation,
    ) -> io::Result<()> {
        let r: &dyn Reactor = &**reactor;
        let (local, peer) = connected_pair()?;
        // With one unread byte the local end is readable and writable at once,
        // so only the interest set decides which direction may be reported.
        send(&peer, b"x")?;
        let token = Token::new(103);
        r.register(&local, token, Interest::READABLE)
            .map_err(during("register"))?;
        let seen = wait_for(r, token, obs)?;
        expect_direction(obs, "READABLE interest", &seen, token, true);
        r.modify(token, Interest::WRITABLE)
            .map_err(during("modify to WRITABLE"))?;
        let seen = wait_for(r, token, obs)?;
        expect_direction(obs, "after modify to WRITABLE", &seen, token, false);
        r.modify(token, Interest::READABLE)
            .map_err(during("modify to READABLE"))?;
        let seen = wait_for(r, token, obs)?;
        expect_direction(obs, "after modify back to READABLE", &seen, token, true);
        r.deregister(token).map_err(during("deregister"))?;
        Ok(())
    }

    fn deregister_stops_events(reactor: &Arc<dyn Reactor>, obs: &mut Observation) -> io::Result<()> {
        let r: &dyn Reactor = &**reactor;
        let (local, peer) = connected_pair()?;
        let token = Token::new(104);
        r.register(&local, token, Interest::READABLE)
            .map_err(during("register"))?;
        let registered = r.registration_count();
        // Readiness is pending in the kernel, not yet polled, when deregister runs.
        send(&peer, b"x")?;
        r.deregister(token).map_err(during("deregister"))?;
        let remaining = r.registration_count();
        obs.require(registered == 1 && remaining == 0, || {
            format!("registration_count went {registered} -> {remaining}, expected 1 -> 0")
        });
        obs.note(format!("registration_count: {registered} -> {remaining}"));
        send(&peer, b"y")?;
        let after = quiet(r, obs)?;
        obs.require(after.is_empty(), || {
            format!("events after deregister: {}", list(&after))
        });
        obs.note(format!("events after deregister: {}", list(&after)));
        Ok(())
    }

    fn registration_errors(reactor: &Arc<dyn Reactor>, obs: &mut Observation) -> io::Result<()> {
        let r: &dyn Reactor = &**reactor;
        let (local, _peer) = connected_pair()?;
        let (other, _other_peer) = connected_pair()?;
        let token = Token::new(105);
        let spare = Token::new(106);
        let unknown = Token::new(107);
        r.register(&local, token, Interest::READABLE)
            .map_err(during("register"))?;
        expect_error(
            obs,
            "same source, same token",
            r.register(&local, token, Interest::READABLE),
            io::ErrorKind::AlreadyExists,
        );
        expect_error(
            obs,
            "other source, same token",
            r.register(&other, token, Interest::READABLE),
            io::ErrorKind::AlreadyExists,
        );
        let same_source = r.register(&local, spare, Interest::READABLE);
        let same_source_accepted = same_source.is_ok();
        expect_error(
            obs,
            "same source, new token",
            same_source,
            io::ErrorKind::AlreadyExists,
        );
        if same_source_accepted {
            let _ = r.deregister(spare);
        }
        let count = r.registration_count();
        obs.require(count == 1, || {
            format!("registration_count is {count} after rejected registrations, expected 1")
        });
        obs.note(format!("registration_count after rejected registrations: {count}"));
        expect_error(
            obs,
            "modify of an unknown token",
            r.modify(unknown, Interest::READABLE),
            io::ErrorKind::NotFound,
        );
        expect_error(
            obs,
            "deregister of an unknown token",
            r.deregister(unknown),
            io::ErrorKind::NotFound,
        );
        r.deregister(token).map_err(during("deregister"))?;
        expect_error(
            obs,
            "second deregister",
            r.deregister(token),
            io::ErrorKind::NotFound,
        );
        expect_error(
            obs,
            "modify after deregister",
            r.modify(token, Interest::READABLE),
            io::ErrorKind::NotFound,
        );
        let remaining = r.registration_count();
        obs.require(remaining == 0, || {
            format!("registration_count is {remaining} at the end, expected 0")
        });
        obs.note(format!("registration_count at the end: {remaining}"));
        Ok(())
    }

    /// Trace class shared by every accepted rejection of an invalid descriptor.
    const REJECTED_INVALID_DESCRIPTOR: &str = "rejected-invalid-descriptor";

    /// Classifies one invalid-descriptor registration outcome, the same way on
    /// every backend.
    ///
    /// The trait documents `InvalidInput` and platform errors from the
    /// registration syscall (mod.rs:991-993), and the in-crate epoll suite
    /// pins raw `EBADF` (epoll_conformance_tests.rs:950-964). So an `Err`
    /// whose kind is `InvalidInput`, or whose raw errno is `EBADF`, conforms
    /// and is recorded as one normalized class: epoll (`InvalidInput` for
    /// `RawFd::MAX`) and io_uring (`EBADF`) then agree in the differential.
    /// `Ok` and every other error are recorded verbatim and are violations.
    fn judge_invalid_descriptor(obs: &mut Observation, label: &str, outcome: &io::Result<()>) {
        match outcome {
            Err(err)
                if err.kind() == io::ErrorKind::InvalidInput
                    || err.raw_os_error() == Some(libc::EBADF) =>
            {
                obs.note(format!("{label}: {REJECTED_INVALID_DESCRIPTOR}"));
            }
            _ => {
                obs.note(format!("{label}: {}", describe_outcome(outcome)));
                obs.violation(format!(
                    "{label}: expected Err(InvalidInput) or raw EBADF (mod.rs:991-993), got {}",
                    describe_outcome(outcome)
                ));
            }
        }
    }

    fn invalid_descriptor_rejected(
        reactor: &Arc<dyn Reactor>,
        obs: &mut Observation,
    ) -> io::Result<()> {
        let r: &dyn Reactor = &**reactor;
        // -1 is the "holds no descriptor" sentinel; RawFd::MAX is above the
        // largest fs.nr_open Linux accepts, so it can never name an open file.
        let cases = [
            ("descriptor -1", -1, Token::new(108)),
            ("descriptor RawFd::MAX", RawFd::MAX, Token::new(109)),
        ];
        for (label, descriptor, token) in cases {
            let outcome = r.register(&DescriptorNumber(descriptor), token, Interest::READABLE);
            judge_invalid_descriptor(obs, label, &outcome);
            if outcome.is_ok() {
                let _ = r.deregister(token);
            }
        }
        let count = r.registration_count();
        obs.require(count == 0, || {
            format!("registration_count is {count} after rejected descriptors, expected 0")
        });
        obs.note(format!("registration_count after rejected descriptors: {count}"));
        Ok(())
    }

    fn poll_timeout_returns_zero(
        reactor: &Arc<dyn Reactor>,
        obs: &mut Observation,
    ) -> io::Result<()> {
        let r: &dyn Reactor = &**reactor;
        let (local, _peer) = connected_pair()?;
        let token = Token::new(110);
        // Registered but never ready.
        r.register(&local, token, Interest::READABLE)
            .map_err(during("register"))?;
        let mut events = Events::with_capacity(8);
        let timeouts = [
            ("Some(100ms)", Duration::from_millis(100)),
            ("Some(ZERO)", Duration::ZERO),
        ];
        for (label, timeout) in timeouts {
            let started = Instant::now();
            let seen = poll_once(r, &mut events, Some(timeout), obs)?;
            let elapsed = started.elapsed();
            obs.require(seen.is_empty(), || {
                format!("poll {label} with nothing ready returned events: {}", list(&seen))
            });
            obs.require(elapsed < ELAPSED_CEILING, || {
                format!("poll {label} took {elapsed:?}, ceiling {ELAPSED_CEILING:?}")
            });
            obs.note(format!(
                "poll {label} with nothing ready: {} event(s)",
                seen.len()
            ));
        }
        r.deregister(token).map_err(during("deregister"))?;
        Ok(())
    }

    fn wake_ends_blocking_poll(reactor: &Arc<dyn Reactor>, obs: &mut Observation) -> io::Result<()> {
        let r: &dyn Reactor = &**reactor;
        // An idle registration: writing to its peer releases the poll thread
        // if wake() does not, so a failed wake() does not strand the thread.
        let (local, peer) = connected_pair()?;
        let token = Token::new(111);
        r.register(&local, token, Interest::READABLE)
            .map_err(during("register"))?;
        let (poller, from_poller) = spawn_blocking_poll(reactor, "reactor-wake-poll")?;
        if !await_entering(obs, &from_poller) {
            let _ = r.wake();
        } else {
            match from_poller.recv_timeout(QUIET_WINDOW) {
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    obs.note("poll(None) with nothing ready: still blocked");
                    if let Err(err) = r.wake() {
                        obs.violation(format!("wake() failed: {err}"));
                    }
                    match from_poller.recv_timeout(EVENT_DEADLINE) {
                        Ok(PollerMessage::Returned(Ok(seen))) => {
                            obs.require(seen.is_empty(), || {
                                format!(
                                    "the woken poll reported events with nothing ready: {}",
                                    list(&seen)
                                )
                            });
                            obs.note(format!(
                                "after wake() from another thread: Ok, events: {}",
                                list(&seen)
                            ));
                        }
                        Ok(PollerMessage::Returned(Err(err))) => {
                            obs.violation(format!("the woken poll(None) failed: {err}"));
                            obs.note(format!(
                                "after wake() from another thread: Err({})",
                                describe_error(&err)
                            ));
                        }
                        Ok(PollerMessage::Entering) | Err(_) => {
                            obs.violation(format!(
                                "poll(None) was still blocked {EVENT_DEADLINE:?} after wake() \
                                 from another thread"
                            ));
                            obs.note("after wake() from another thread: still blocked");
                            send(&peer, b"x")?;
                            let _ = from_poller.recv_timeout(EVENT_DEADLINE);
                        }
                    }
                }
                Ok(message) => {
                    obs.violation(format!(
                        "poll(None) returned before wake() with nothing ready: {}",
                        describe_message(&message)
                    ));
                    obs.note("poll(None) with nothing ready: returned early");
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    obs.violation("the poll(None) thread exited without reporting");
                    obs.note("poll(None) thread: exited without reporting");
                }
            }
        }
        // A poll thread that never returned may still hold backend locks (the
        // io_uring ring); cleanup through the reactor runs only once it exited.
        let poller_exited =
            !join_within(obs, vec![poller], "poll(None) thread", EVENT_DEADLINE).is_empty();
        if poller_exited {
            r.deregister(token).map_err(during("deregister"))?;
        }
        Ok(())
    }

    fn peer_close_reports_hangup(
        reactor: &Arc<dyn Reactor>,
        obs: &mut Observation,
    ) -> io::Result<()> {
        let r: &dyn Reactor = &**reactor;

        // With Interest::HUP the close itself must be reported as hang-up.
        let (local, peer) = connected_pair()?;
        let hup_token = Token::new(112);
        r.register(&local, hup_token, Interest::READABLE | Interest::HUP)
            .map_err(during("register READABLE|HUP"))?;
        // The peer holds nothing unread, so this is an orderly close.
        drop(peer);
        let seen = wait_for(r, hup_token, obs)?;
        expect_only(obs, &seen, &[hup_token]);
        if let Some(ready) = delivered(obs, "peer close under READABLE|HUP", &seen, hup_token) {
            obs.require(ready.is_hup(), || {
                format!("peer close under READABLE|HUP lacks HUP ({})", flags(ready))
            });
        }
        r.deregister(hup_token).map_err(during("deregister"))?;

        // With READABLE alone, end of stream (read() returns 0 without
        // blocking) must still wake a reader with read readiness.
        let (eof_local, eof_peer) = connected_pair()?;
        let eof_token = Token::new(113);
        r.register(&eof_local, eof_token, Interest::READABLE)
            .map_err(during("register READABLE"))?;
        drop(eof_peer);
        let seen = wait_for(r, eof_token, obs)?;
        expect_readable(obs, "peer close under READABLE", &seen, eof_token);
        r.deregister(eof_token).map_err(during("deregister"))?;
        Ok(())
    }

    fn batch_delivers_each_token_once(
        reactor: &Arc<dyn Reactor>,
        obs: &mut Observation,
    ) -> io::Result<()> {
        let r: &dyn Reactor = &**reactor;
        let mut pairs = Vec::with_capacity(BATCH_SOURCES);
        for offset in 0..BATCH_SOURCES {
            let (local, peer) = connected_pair()?;
            r.register(
                &local,
                Token::new(BATCH_TOKEN_BASE + offset),
                Interest::READABLE,
            )
            .map_err(during("register batch source"))?;
            pairs.push((local, peer));
        }
        let count = r.registration_count();
        obs.require(count == BATCH_SOURCES, || {
            format!("registration_count is {count} after {BATCH_SOURCES} registrations")
        });
        for (_, peer) in &pairs {
            send(peer, b"x")?;
        }
        let mut tally = Tally::new(BATCH_TOKEN_BASE, BATCH_SOURCES);
        // Smaller than the batch, so a backend that honours the capacity has
        // to spread delivery over several polls.
        let mut events = Events::with_capacity(16);
        let deadline = Instant::now() + EVENT_DEADLINE;
        while !tally.complete() && Instant::now() < deadline {
            for (token, ready) in poll_once(r, &mut events, Some(POLL_SLICE), obs)? {
                tally.record(token, ready);
            }
        }
        // Oneshot registrations must not deliver any source a second time.
        for (token, ready) in quiet(r, obs)? {
            tally.record(token, ready);
        }
        tally.judge(obs);
        for offset in 0..BATCH_SOURCES {
            r.deregister(Token::new(BATCH_TOKEN_BASE + offset))
                .map_err(during("deregister batch source"))?;
        }
        let remaining = r.registration_count();
        obs.require(remaining == 0, || {
            format!("registration_count is {remaining} after the batch was removed")
        });
        Ok(())
    }

    type KeptSource = (Token, UnixStream, UnixStream);

    fn churn_worker(r: &dyn Reactor, index: usize) -> Result<Vec<KeptSource>, String> {
        let first = churn_first_token(index);
        let mut kept = Vec::with_capacity(CHURN_KEPT);
        for slot in 0..CHURN_KEPT {
            let (local, peer) =
                connected_pair().map_err(|err| churn_failure(index, "pair", &err))?;
            let token = Token::new(first + slot);
            r.register(&local, token, Interest::READABLE)
                .map_err(|err| churn_failure(index, "register kept source", &err))?;
            kept.push((token, local, peer));
        }
        for round in 0..CHURN_ROUNDS {
            let (local, peer) =
                connected_pair().map_err(|err| churn_failure(index, "pair", &err))?;
            let token = Token::new(first + CHURN_KEPT + round);
            r.register(&local, token, Interest::READABLE)
                .map_err(|err| churn_failure(index, "register", &err))?;
            // Gives the poller readiness to deliver while registrations churn.
            send(&peer, b"x").map_err(|err| churn_failure(index, "write", &err))?;
            r.deregister(token)
                .map_err(|err| churn_failure(index, "deregister", &err))?;
        }
        Ok(kept)
    }

    fn concurrent_registration_churn(
        reactor: &Arc<dyn Reactor>,
        obs: &mut Observation,
    ) -> io::Result<()> {
        let workers = Arc::clone(reactor);
        churn_contract(
            reactor,
            obs,
            move |index| churn_worker(&*workers, index),
            |record: &KeptSource| record.0,
        )
    }

    fn register_while_poll_blocked(
        reactor: &Arc<dyn Reactor>,
        gap: Option<&'static str>,
        obs: &mut Observation,
    ) -> io::Result<()> {
        let r: &dyn Reactor = &**reactor;
        let (local, peer) = connected_pair()?;
        // The source is readable before it is registered.
        send(&peer, b"x")?;
        let local = Arc::new(local);
        let token = Token::new(114);
        let (poller, from_poller) = spawn_blocking_poll(reactor, "reactor-blocked-poll")?;
        if !await_entering(obs, &from_poller) {
            let _ = r.wake();
            join_within(obs, vec![poller], "poll(None) thread", EVENT_DEADLINE);
            return Ok(());
        }
        // This window only lets the poll thread reach its kernel wait. A
        // correct backend passes whether or not it got there, so no verdict
        // depends on the window; it decides whether a stall can be observed.
        if let Ok(message) = from_poller.recv_timeout(QUIET_WINDOW) {
            obs.violation(format!(
                "poll(None) returned with nothing registered and no wake(): {}",
                describe_message(&message)
            ));
            obs.note("poll(None) with nothing registered: returned early");
            join_within(obs, vec![poller], "poll(None) thread", EVENT_DEADLINE);
            return Ok(());
        }

        let (registered_tx, registered_rx) = mpsc::channel();
        let spawned = {
            let reactor = Arc::clone(reactor);
            let local = Arc::clone(&local);
            thread::Builder::new()
                .name("reactor-registrar".to_owned())
                .spawn(move || {
                    let registrar: &dyn Reactor = &*reactor;
                    let _ = registered_tx.send(registrar.register(
                        &*local,
                        token,
                        Interest::READABLE,
                    ));
                })
        };
        let registrar = match spawned {
            Ok(handle) => handle,
            Err(err) => {
                let _ = r.wake();
                join_within(obs, vec![poller], "poll(None) thread", EVENT_DEADLINE);
                return Err(during("spawn registrar")(err));
            }
        };

        // Exactly one trace line describes the register, so the trace stays
        // line-aligned with a backend whose register never stalls.
        let mut registered = false;
        let mut stall_gap = None;
        let mut poller_message = None;
        match registered_rx.recv_timeout(EVENT_DEADLINE) {
            Ok(outcome) => {
                obs.note(format!(
                    "register while another thread is blocked in poll(None): {}",
                    describe_outcome(&outcome)
                ));
                registered = outcome.is_ok();
                if let Err(err) = outcome {
                    obs.violation(format!("register during a blocked poll failed: {err}"));
                }
            }
            Err(_) => {
                // The stall is the tracked gap only while the poll is still
                // blocked; a poll that already returned explains nothing.
                let poll_still_blocked = match from_poller.try_recv() {
                    Ok(message) => {
                        poller_message = Some(message);
                        false
                    }
                    Err(mpsc::TryRecvError::Empty) => true,
                    Err(mpsc::TryRecvError::Disconnected) => false,
                };
                // Always wake: it releases the poll, and with it the stalled
                // register, so no thread is left waiting on the reactor.
                let woke = r.wake();
                let after_wake = registered_rx.recv_timeout(EVENT_DEADLINE);
                registered = matches!(after_wake, Ok(Ok(())));
                let line = match &after_wake {
                    Ok(outcome) => format!(
                        "register while another thread is blocked in poll(None): stalled until \
                         wake(), then {}",
                        describe_outcome(outcome)
                    ),
                    Err(_) => "register while another thread is blocked in poll(None): stalled, \
                               and still stalled after wake()"
                        .to_owned(),
                };
                match gap {
                    Some(gap) if poll_still_blocked && woke.is_ok() && registered => {
                        stall_gap = Some(gap);
                        obs.gap_note(gap, line);
                    }
                    _ => {
                        obs.note(line);
                        obs.violation(format!(
                            "register did not return within {EVENT_DEADLINE:?} while another \
                             thread was blocked in poll(None)"
                        ));
                        if !poll_still_blocked {
                            obs.violation("register stalled although poll(None) had already returned");
                        }
                        if let Err(err) = &woke {
                            obs.violation(format!("wake() failed: {err}"));
                        }
                        match &after_wake {
                            Ok(Ok(())) => {}
                            Ok(Err(err)) => {
                                obs.violation(format!("register failed after wake(): {err}"));
                            }
                            Err(_) => obs.violation("register was still stalled after wake()"),
                        }
                    }
                }
            }
        }

        // Whether the already-blocked poll sees the new source is recorded for
        // the differential; the contract only needs its readiness delivered.
        // After a gap stall the poll was released by wake() before the
        // register ran, so its answer is part of the same gap.
        let poller_message = match poller_message {
            Some(message) => Ok(message),
            None => from_poller.recv_timeout(EVENT_DEADLINE),
        };
        let mut readiness_delivered = false;
        match poller_message {
            Ok(PollerMessage::Returned(Ok(seen))) => {
                let observed =
                    readiness_of(&seen, token).is_some_and(|ready| ready.is_readable());
                let line = format!(
                    "the blocked poll observed the new source: {}",
                    yes_no(observed)
                );
                match stall_gap {
                    Some(gap) => obs.gap_note(gap, line),
                    None => obs.note(line),
                }
                readiness_delivered = observed;
            }
            Ok(PollerMessage::Returned(Err(err))) => {
                obs.violation(format!("the blocked poll(None) failed: {err}"));
                obs.note(format!("the blocked poll: Err({})", describe_error(&err)));
            }
            Ok(PollerMessage::Entering) | Err(_) => {
                obs.note("the blocked poll observed the new source: no");
                let _ = r.wake();
                let _ = from_poller.recv_timeout(EVENT_DEADLINE);
            }
        }
        // Follow-up polls and cleanup go through the reactor from this thread,
        // so they run only after both contract threads have exited; a thread
        // that never returned may still hold backend locks.
        let exited = join_within(
            obs,
            vec![poller, registrar],
            "blocked-poll contract thread",
            EVENT_DEADLINE,
        );
        if exited.len() < 2 {
            obs.note("follow-up skipped: a contract thread is still running");
            return Ok(());
        }
        if registered && !readiness_delivered {
            let seen = wait_for(r, token, obs)?;
            readiness_delivered =
                readiness_of(&seen, token).is_some_and(|ready| ready.is_readable());
        }
        obs.require(readiness_delivered, || {
            "readiness of the source registered during a blocked poll was never delivered"
                .to_owned()
        });
        obs.note(format!("readiness delivered: {}", yes_no(readiness_delivered)));
        obs.gap_closed_remark(gap, "register returned while poll(None) was blocked");
        if registered {
            r.deregister(token).map_err(during("deregister"))?;
        }
        Ok(())
    }

    fn oneshot_default_requires_rearm(
        reactor: &Arc<dyn Reactor>,
        obs: &mut Observation,
    ) -> io::Result<()> {
        let r: &dyn Reactor = &**reactor;
        let (local, peer) = connected_pair()?;
        let token = Token::new(115);
        r.register(&local, token, Interest::READABLE)
            .map_err(during("register"))?;
        send(&peer, b"x")?;
        let first = wait_for(r, token, obs)?;
        expect_readable(obs, "first readiness", &first, token);
        // The byte stays unread, so the source stays readable; a oneshot
        // registration must stay silent until modify() re-arms it.
        let again = quiet(r, obs)?;
        obs.require(again.is_empty(), || {
            format!(
                "a still-readable source was delivered again without modify(): {}",
                list(&again)
            )
        });
        obs.note(format!("again without modify: {}", list(&again)));
        r.modify(token, Interest::READABLE)
            .map_err(during("modify re-arm"))?;
        let rearmed = wait_for(r, token, obs)?;
        expect_readable(obs, "after the modify re-arm", &rearmed, token);
        r.deregister(token).map_err(during("deregister"))?;
        Ok(())
    }

    fn edge_triggered_redelivers_after_drain(
        reactor: &Arc<dyn Reactor>,
        obs: &mut Observation,
    ) -> io::Result<()> {
        let r: &dyn Reactor = &**reactor;
        let (local, peer) = connected_pair()?;
        let token = Token::new(116);
        match r.register(&local, token, Interest::READABLE | Interest::EDGE_TRIGGERED) {
            Ok(()) => obs.note("EDGE_TRIGGERED registration: accepted"),
            // mod.rs:935-937 makes edge triggering conditional on backend
            // support; a backend may refuse the flag instead of honouring it.
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::Unsupported | io::ErrorKind::InvalidInput
                ) =>
            {
                obs.note(format!(
                    "EDGE_TRIGGERED registration: declined ({})",
                    describe_error(&err)
                ));
                obs.declined = Some(format!(
                    "the backend declined Interest::EDGE_TRIGGERED: {}",
                    describe_error(&err)
                ));
                return Ok(());
            }
            Err(err) => return Err(during("register")(err)),
        }
        send(&peer, b"x")?;
        let first = wait_for(r, token, obs)?;
        expect_readable(obs, "first edge", &first, token);
        let drained = drain(&local)?;
        obs.note(format!("bytes drained: {drained}"));
        let idle = quiet(r, obs)?;
        obs.require(idle.is_empty(), || {
            format!(
                "a drained source was delivered without a new edge: {}",
                list(&idle)
            )
        });
        obs.note(format!("after the drain, no new edge: {}", list(&idle)));
        send(&peer, b"y")?;
        let second = wait_for(r, token, obs)?;
        expect_only(obs, &second, &[token]);
        match readiness_of(&second, token) {
            Some(ready) => {
                obs.note(format!("new edge without modify: {}", flags(ready)));
                obs.require(ready.is_readable(), || {
                    format!("the new edge lacks read readiness ({})", flags(ready))
                });
            }
            // Every backend that accepts the flag must deliver this edge; on
            // io_uring this was the tracked gap asupersync-ubwvb0.
            None => {
                obs.note("new edge without modify: none");
                obs.violation(format!(
                    "the EDGE_TRIGGERED registration was accepted, but a new edge after a \
                     full drain produced no event within {EVENT_DEADLINE:?} without modify(): \
                     the backend delivered it as oneshot"
                ));
            }
        }
        r.deregister(token).map_err(during("deregister"))?;
        Ok(())
    }

    /// The invalid-descriptor judge, which every backend shares, must pass
    /// both documented rejections as one class and fail everything else.
    #[cfg(test)]
    pub(super) fn invalid_descriptor_judge_controls() {
        let contract = Contract::InvalidDescriptorRejected;
        for kind in [RowKind::Epoll, RowKind::IoUring, RowKind::Lab] {
            assert_eq!(
                known_gap(contract, kind),
                None,
                "invalid-descriptor rejection carries no tracked gap on {kind:?}"
            );
        }

        let judged = |outcome: io::Result<()>| {
            let mut observation = Observation::default();
            judge_invalid_descriptor(&mut observation, "descriptor", &outcome);
            observation
        };
        let class_line = format!("descriptor: {REJECTED_INVALID_DESCRIPTOR}");

        // InvalidInput (custom or from EINVAL) and raw EBADF all conform.
        let invalid_input = judged(Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid descriptor",
        )));
        let einval = judged(Err(io::Error::from_raw_os_error(libc::EINVAL)));
        let ebadf = judged(Err(io::Error::from_raw_os_error(libc::EBADF)));
        for conforming in [&invalid_input, &einval, &ebadf] {
            assert_eq!(conforming.verdict(), TestVerdict::Pass);
            assert_eq!(conforming.trace, vec![class_line.clone()]);
            assert!(conforming.gap.is_none() && conforming.remarks.is_empty());
        }
        // epoll's InvalidInput and io_uring's EBADF agree in the differential.
        assert_eq!(
            differential_verdict(contract, Some(&invalid_input), &ebadf),
            TestVerdict::Pass
        );

        // Acceptance and any other error fail, are recorded verbatim, and
        // still diverge from a conforming backend.
        for outcome in [Err(io::Error::from_raw_os_error(libc::EPERM)), Ok(())] {
            let stray = judged(outcome);
            assert!(
                matches!(stray.verdict(), TestVerdict::Fail(_)),
                "only InvalidInput or raw EBADF conforms, got {:?}",
                stray.verdict()
            );
            assert_ne!(stray.trace, vec![class_line.clone()]);
            assert!(matches!(
                differential_verdict(contract, Some(&invalid_input), &stray),
                TestVerdict::Fail(_)
            ));
        }
    }

    /// The probes must see readiness that occurs, and must report its absence.
    #[cfg(test)]
    pub(super) fn probe_controls() {
        let reactor = epoll().expect("EpollReactor::new");
        let r: &dyn Reactor = &*reactor;
        let (ready_local, ready_peer) = connected_pair().expect("ready pair");
        let (idle_local, _idle_peer) = connected_pair().expect("idle pair");
        let ready = Token::new(9_101);
        let idle = Token::new(9_102);
        r.register(&ready_local, ready, Interest::READABLE)
            .expect("register the ready source");
        r.register(&idle_local, idle, Interest::READABLE)
            .expect("register the idle source");
        send(&ready_peer, b"x").expect("peer write");

        let mut obs = Observation::default();
        let window = quiet(r, &mut obs).expect("quiet window");
        assert!(
            readiness_of(&window, ready).is_some_and(|flags| flags.is_readable()),
            "quiet() must surface readiness that occurs inside its window, saw {}",
            list(&window)
        );

        let started = Instant::now();
        let waited = wait_for(r, idle, &mut obs).expect("wait for the idle source");
        let elapsed = started.elapsed();
        assert!(
            readiness_of(&waited, idle).is_none(),
            "wait_for() reported a source that never became ready: {}",
            list(&waited)
        );
        assert!(
            elapsed >= EVENT_DEADLINE && elapsed < EVENT_DEADLINE + ELAPSED_CEILING,
            "wait_for() must give up at its deadline, took {elapsed:?}"
        );
        assert!(
            obs.violations.is_empty(),
            "probe bookkeeping recorded violations: {:?}",
            obs.violations
        );
        r.deregister(ready).expect("deregister the ready source");
        r.deregister(idle).expect("deregister the idle source");
    }
}

/// Contracts run against `LabReactor`, whose readiness is injected.
#[cfg(any(unix, windows))]
mod lab_checks {
    use super::*;

    /// A source that only names lab registrations; `LabReactor::register`
    /// never inspects it (lab.rs:720).
    pub(super) fn naming_source() -> io::Result<Arc<dyn Source>> {
        #[cfg(unix)]
        {
            let (local, _peer) = std::os::unix::net::UnixStream::pair()?;
            let source: Arc<dyn Source> = Arc::new(local);
            Ok(source)
        }
        #[cfg(windows)]
        {
            let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
            let source: Arc<dyn Source> = Arc::new(listener);
            Ok(source)
        }
    }

    pub(super) fn run(contract: Contract) -> Observation {
        observe(|obs| {
            let lab = Arc::new(LabReactor::new());
            let source = naming_source().map_err(during("naming source"))?;
            match contract {
                Contract::ReadableAfterPeerWrite => readable(&lab, &*source, obs),
                Contract::WritableOnConnectedSocket => writable(&lab, &*source, obs),
                Contract::ModifySwitchesInterest => modify(&lab, &*source, obs),
                Contract::DeregisterStopsEvents => deregister(&lab, &*source, obs),
                Contract::RegistrationErrors => errors(&lab, &*source, obs),
                Contract::PollTimeoutReturnsZero => poll_timeout(&lab, &*source, obs),
                Contract::WakeEndsBlockingPoll => wake(&lab, &*source, obs),
                Contract::PeerCloseReportsHangup => peer_close(&lab, &*source, obs),
                Contract::BatchDeliversEachTokenOnce => batch(&lab, &*source, obs),
                Contract::ConcurrentRegistrationChurn => churn(&lab, &source, obs),
                Contract::InvalidDescriptorRejected
                | Contract::RegisterWhilePollBlocked
                | Contract::OneshotDefaultRequiresRearm
                | Contract::EdgeTriggeredRedeliversAfterDrain => {
                    obs.violation(format!(
                        "{} is not expressible on LabReactor and must not be scheduled",
                        contract.row_name(RowKind::Lab)
                    ));
                    Ok(())
                }
            }
        })
    }

    /// Delivers everything due at the current virtual instant.
    fn due_now(r: &dyn Reactor, obs: &mut Observation) -> io::Result<Vec<(Token, Interest)>> {
        let mut events = Events::with_capacity(64);
        poll_once(r, &mut events, Some(Duration::ZERO), obs)
    }

    fn readable(lab: &Arc<LabReactor>, source: &dyn Source, obs: &mut Observation) -> io::Result<()> {
        let r: &dyn Reactor = &**lab;
        let token = Token::new(201);
        r.register(source, token, Interest::READABLE)
            .map_err(during("register"))?;
        let count = r.registration_count();
        obs.require(count == 1, || {
            format!("registration_count is {count} after one register")
        });
        let before = due_now(r, obs)?;
        obs.require(before.is_empty(), || {
            format!("events before any readiness: {}", list(&before))
        });
        obs.note(format!("before set_ready: {}", list(&before)));
        lab.set_ready(token, Event::readable(token));
        let seen = due_now(r, obs)?;
        expect_readable(obs, "after set_ready(readable)", &seen, token);
        r.deregister(token).map_err(during("deregister"))?;
        Ok(())
    }

    fn writable(lab: &Arc<LabReactor>, source: &dyn Source, obs: &mut Observation) -> io::Result<()> {
        let r: &dyn Reactor = &**lab;
        let token = Token::new(202);
        r.register(source, token, Interest::WRITABLE)
            .map_err(during("register"))?;
        lab.set_ready(token, Event::writable(token));
        let seen = due_now(r, obs)?;
        expect_direction(obs, "after set_ready(writable)", &seen, token, false);
        r.deregister(token).map_err(during("deregister"))?;
        Ok(())
    }

    fn modify(lab: &Arc<LabReactor>, source: &dyn Source, obs: &mut Observation) -> io::Result<()> {
        let r: &dyn Reactor = &**lab;
        let token = Token::new(203);
        let both = Interest::READABLE | Interest::WRITABLE;
        r.register(source, token, Interest::READABLE)
            .map_err(during("register"))?;
        lab.set_ready(token, Event::new(token, both));
        let seen = due_now(r, obs)?;
        expect_direction(obs, "READABLE interest", &seen, token, true);
        r.modify(token, Interest::WRITABLE)
            .map_err(during("modify to WRITABLE"))?;
        lab.set_ready(token, Event::new(token, both));
        let seen = due_now(r, obs)?;
        expect_direction(obs, "after modify to WRITABLE", &seen, token, false);
        r.modify(token, Interest::READABLE)
            .map_err(during("modify to READABLE"))?;
        lab.set_ready(token, Event::new(token, both));
        let seen = due_now(r, obs)?;
        expect_direction(obs, "after modify back to READABLE", &seen, token, true);
        r.deregister(token).map_err(during("deregister"))?;
        Ok(())
    }

    fn deregister(lab: &Arc<LabReactor>, source: &dyn Source, obs: &mut Observation) -> io::Result<()> {
        let r: &dyn Reactor = &**lab;
        let token = Token::new(204);
        r.register(source, token, Interest::READABLE)
            .map_err(during("register"))?;
        let registered = r.registration_count();
        // Readiness is queued, not yet polled, when deregister runs.
        lab.set_ready(token, Event::readable(token));
        r.deregister(token).map_err(during("deregister"))?;
        let remaining = r.registration_count();
        obs.require(registered == 1 && remaining == 0, || {
            format!("registration_count went {registered} -> {remaining}, expected 1 -> 0")
        });
        obs.note(format!("registration_count: {registered} -> {remaining}"));
        lab.set_ready(token, Event::readable(token));
        let after = due_now(r, obs)?;
        obs.require(after.is_empty(), || {
            format!("events after deregister: {}", list(&after))
        });
        obs.note(format!("events after deregister: {}", list(&after)));
        Ok(())
    }

    fn errors(lab: &Arc<LabReactor>, source: &dyn Source, obs: &mut Observation) -> io::Result<()> {
        let r: &dyn Reactor = &**lab;
        let token = Token::new(205);
        let unknown = Token::new(206);
        r.register(source, token, Interest::READABLE)
            .map_err(during("register"))?;
        expect_error(
            obs,
            "same source, same token",
            r.register(source, token, Interest::READABLE),
            io::ErrorKind::AlreadyExists,
        );
        // LabReactor keys registrations by token only and never inspects the
        // source (lab.rs:720), so a source registered twice is not modeled.
        let count = r.registration_count();
        obs.require(count == 1, || {
            format!("registration_count is {count} after a rejected registration, expected 1")
        });
        expect_error(
            obs,
            "modify of an unknown token",
            r.modify(unknown, Interest::READABLE),
            io::ErrorKind::NotFound,
        );
        expect_error(
            obs,
            "deregister of an unknown token",
            r.deregister(unknown),
            io::ErrorKind::NotFound,
        );
        r.deregister(token).map_err(during("deregister"))?;
        expect_error(
            obs,
            "second deregister",
            r.deregister(token),
            io::ErrorKind::NotFound,
        );
        expect_error(
            obs,
            "modify after deregister",
            r.modify(token, Interest::READABLE),
            io::ErrorKind::NotFound,
        );
        let remaining = r.registration_count();
        obs.require(remaining == 0, || {
            format!("registration_count is {remaining} at the end, expected 0")
        });
        Ok(())
    }

    fn poll_timeout(lab: &Arc<LabReactor>, source: &dyn Source, obs: &mut Observation) -> io::Result<()> {
        let r: &dyn Reactor = &**lab;
        let token = Token::new(207);
        r.register(source, token, Interest::READABLE)
            .map_err(during("register"))?;
        let mut events = Events::with_capacity(8);

        let start = lab.now();
        let started = Instant::now();
        let seen = poll_once(r, &mut events, Some(Duration::from_millis(100)), obs)?;
        let elapsed = started.elapsed();
        let advanced = lab.now().as_nanos().saturating_sub(start.as_nanos());
        obs.require(seen.is_empty(), || {
            format!("poll Some(100ms) with nothing ready returned events: {}", list(&seen))
        });
        obs.require(elapsed < ELAPSED_CEILING, || {
            format!("poll Some(100ms) took {elapsed:?} of wall time, ceiling {ELAPSED_CEILING:?}")
        });
        // Virtual time advances only through poll timeouts (lab.rs:9, 784-802).
        obs.require(advanced == 100_000_000, || {
            format!("poll Some(100ms) advanced the virtual clock by {advanced}ns, expected 100ms")
        });
        obs.note(format!(
            "poll Some(100ms) with nothing ready: {} event(s)",
            seen.len()
        ));

        let start = lab.now();
        let seen = poll_once(r, &mut events, Some(Duration::ZERO), obs)?;
        let held = lab.now() == start;
        obs.require(seen.is_empty() && held, || {
            format!(
                "poll Some(ZERO) with nothing ready returned {} and {} the virtual clock",
                list(&seen),
                if held { "held" } else { "moved" }
            )
        });
        obs.note(format!(
            "poll Some(ZERO) with nothing ready: {} event(s)",
            seen.len()
        ));
        r.deregister(token).map_err(during("deregister"))?;
        Ok(())
    }

    /// `LabReactor::poll` never blocks, so the expressible form of the wake
    /// contract is: a `wake()` from another thread makes the next timed poll
    /// return at once, before readiness that is due later (lab.rs:789-791).
    fn wake(lab: &Arc<LabReactor>, source: &dyn Source, obs: &mut Observation) -> io::Result<()> {
        let r: &dyn Reactor = &**lab;
        let token = Token::new(208);
        r.register(source, token, Interest::READABLE)
            .map_err(during("register"))?;
        lab.inject_event(token, Event::readable(token), Duration::from_millis(500));

        let (wake_tx, wake_rx) = mpsc::channel();
        let remote = Arc::clone(lab);
        let waker = thread::Builder::new()
            .name("lab-waker".to_owned())
            .spawn(move || {
                let remote: &dyn Reactor = &*remote;
                let _ = wake_tx.send(remote.wake());
            })
            .map_err(during("spawn waker"))?;
        match wake_rx.recv_timeout(EVENT_DEADLINE) {
            Ok(Ok(())) => obs.note("wake() from another thread: Ok"),
            Ok(Err(err)) => {
                obs.violation(format!("wake() from another thread failed: {err}"));
                obs.note(format!(
                    "wake() from another thread: Err({})",
                    describe_error(&err)
                ));
            }
            Err(_) => {
                obs.violation("the wake() thread did not report within the deadline");
                obs.note("wake() from another thread: no report");
            }
        }
        join_within(obs, vec![waker], "wake() thread", EVENT_DEADLINE);

        let mut events = Events::with_capacity(8);
        let start = lab.now();
        let woken = poll_once(r, &mut events, Some(Duration::from_secs(1)), obs)?;
        let moved = lab.now().as_nanos().saturating_sub(start.as_nanos());
        obs.require(woken.is_empty() && moved == 0, || {
            format!(
                "the poll after wake() should return at once without advancing the virtual \
                 clock; got {} with the clock moved by {moved}ns",
                list(&woken)
            )
        });
        obs.note(format!(
            "poll after wake(): {}, clock moved {moved}ns",
            list(&woken)
        ));

        let next = poll_once(r, &mut events, Some(Duration::from_secs(1)), obs)?;
        let moved = lab.now().as_nanos().saturating_sub(start.as_nanos());
        let ready = readiness_of(&next, token).is_some_and(|ready| ready.is_readable());
        obs.require(ready && moved == 500_000_000, || {
            format!(
                "the following poll should deliver the readiness due at +500ms; got {} with \
                 the clock moved by {moved}ns",
                list(&next)
            )
        });
        obs.note(format!("following poll: {}", list(&next)));
        r.deregister(token).map_err(during("deregister"))?;
        Ok(())
    }

    fn peer_close(lab: &Arc<LabReactor>, source: &dyn Source, obs: &mut Observation) -> io::Result<()> {
        let r: &dyn Reactor = &**lab;
        let token = Token::new(209);
        r.register(source, token, Interest::READABLE | Interest::HUP)
            .map_err(during("register"))?;
        // No readiness is queued: the close alone must surface (lab.rs:552-556).
        lab.inject_close(token).map_err(during("inject_close"))?;
        let seen = due_now(r, obs)?;
        expect_only(obs, &seen, &[token]);
        if let Some(ready) = delivered(obs, "after inject_close", &seen, token) {
            obs.require(ready.is_hup(), || {
                format!("a close under READABLE|HUP lacks HUP ({})", flags(ready))
            });
        }
        // LabReactor reports a close as HUP only (lab.rs:854-861); end-of-stream
        // read readiness under READABLE alone is not modeled.
        r.deregister(token).map_err(during("deregister"))?;
        Ok(())
    }

    fn batch(lab: &Arc<LabReactor>, source: &dyn Source, obs: &mut Observation) -> io::Result<()> {
        let r: &dyn Reactor = &**lab;
        for offset in 0..BATCH_SOURCES {
            r.register(
                source,
                Token::new(BATCH_TOKEN_BASE + offset),
                Interest::READABLE,
            )
            .map_err(during("register batch token"))?;
        }
        let count = r.registration_count();
        obs.require(count == BATCH_SOURCES, || {
            format!("registration_count is {count} after {BATCH_SOURCES} registrations")
        });
        for offset in 0..BATCH_SOURCES {
            let token = Token::new(BATCH_TOKEN_BASE + offset);
            lab.set_ready(token, Event::readable(token));
        }
        let mut tally = Tally::new(BATCH_TOKEN_BASE, BATCH_SOURCES);
        let mut events = Events::with_capacity(16);
        for _ in 0..BATCH_SOURCES {
            if tally.complete() {
                break;
            }
            for (token, ready) in poll_once(r, &mut events, Some(Duration::ZERO), obs)? {
                tally.record(token, ready);
            }
        }
        // Each injected readiness is delivered once; nothing may repeat.
        for (token, ready) in poll_once(r, &mut events, Some(Duration::ZERO), obs)? {
            tally.record(token, ready);
        }
        tally.judge(obs);
        for offset in 0..BATCH_SOURCES {
            r.deregister(Token::new(BATCH_TOKEN_BASE + offset))
                .map_err(during("deregister batch token"))?;
        }
        let remaining = r.registration_count();
        obs.require(remaining == 0, || {
            format!("registration_count is {remaining} after the batch was removed")
        });
        Ok(())
    }

    fn churn(lab: &Arc<LabReactor>, source: &Arc<dyn Source>, obs: &mut Observation) -> io::Result<()> {
        let reactor: Arc<dyn Reactor> = Arc::<LabReactor>::clone(lab);
        let worker_lab = Arc::clone(lab);
        let worker_source = Arc::clone(source);
        churn_contract(
            &reactor,
            obs,
            move |index| {
                let r: &dyn Reactor = &*worker_lab;
                let first = churn_first_token(index);
                let mut kept = Vec::with_capacity(CHURN_KEPT);
                for slot in 0..CHURN_KEPT {
                    let token = Token::new(first + slot);
                    r.register(&*worker_source, token, Interest::READABLE)
                        .map_err(|err| churn_failure(index, "register kept token", &err))?;
                    kept.push(token);
                }
                for round in 0..CHURN_ROUNDS {
                    let token = Token::new(first + CHURN_KEPT + round);
                    r.register(&*worker_source, token, Interest::READABLE)
                        .map_err(|err| churn_failure(index, "register", &err))?;
                    worker_lab.set_ready(token, Event::readable(token));
                    r.deregister(token)
                        .map_err(|err| churn_failure(index, "deregister", &err))?;
                }
                Ok(kept)
            },
            |token: &Token| *token,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Every ExpectedGap row must be one of the tracked io_uring gaps, under
    /// that contract's io_uring row or its differential, with the text verbatim.
    fn assert_gaps_are_tracked(rows: &[ConformanceTestResult]) {
        for row in rows {
            if let TestVerdict::ExpectedGap(message) = &row.verdict {
                let tracked = Contract::ALL.iter().any(|contract| {
                    known_gap(*contract, RowKind::IoUring).is_some_and(|gap| {
                        gap == message.as_str()
                            && (row.test_name == contract.row_name(RowKind::IoUring)
                                || row.test_name == contract.row_name(RowKind::IoUringVsEpoll))
                    })
                });
                assert!(tracked, "{} reports an untracked gap: {message}", row.test_name);
            }
        }
    }

    #[test]
    fn full_suite_covers_required_categories_without_hard_failures() {
        let results = ReactorConformanceHarness::new().run_full_suite();
        // One line per row, so a log shows which backends ran and how each
        // contract was judged, not only that the suite passed.
        for row in &results {
            eprintln!("reactor_conformance row={} verdict={:?}", row.test_name, row.verdict);
        }
        let categories: HashSet<TestCategory> = results.iter().map(|row| row.category).collect();
        for required in [
            TestCategory::IoEventNotification,
            TestCategory::RegistrationLifecycle,
            TestCategory::ThreadSafety,
        ] {
            assert!(
                categories.contains(&required),
                "the reactor suite has no {required:?} row"
            );
        }
        let names: HashSet<&str> = results.iter().map(|row| row.test_name).collect();
        assert_eq!(names.len(), results.len(), "row names must be unique");
        // ExpectedGap counts as successful in CoverageStats and is not a hard
        // failure, so only the tracked gaps may use it.
        assert_gaps_are_tracked(&results);
        let failures: Vec<(&str, &TestVerdict)> = results
            .iter()
            .filter(|row| row.is_hard_failure())
            .map(|row| (row.test_name, &row.verdict))
            .collect();
        assert!(
            failures.is_empty(),
            "reactor contract violations: {failures:#?}"
        );
    }

    #[test]
    fn epoll_rows_run_on_linux_and_are_skipped_elsewhere() {
        let harness = ReactorConformanceHarness::new();
        let (rows, observations) = harness.epoll_rows();
        #[cfg(target_os = "linux")]
        {
            let names: Vec<&str> = rows.iter().map(|row| row.test_name).collect();
            let expected: Vec<&str> = Contract::ALL
                .iter()
                .map(|contract| contract.row_name(RowKind::Epoll))
                .collect();
            assert_eq!(names, expected, "one epoll row per contract, in order");
            assert_eq!(observations.len(), Contract::ALL.len());
            for row in &rows {
                assert!(
                    !matches!(row.verdict, TestVerdict::Skip(_)),
                    "{} was skipped on Linux: {:?}",
                    row.test_name,
                    row.verdict
                );
                assert!(
                    row.duration_micros.is_some(),
                    "{} did not run through the harness",
                    row.test_name
                );
            }
            for (contract, observation) in &observations {
                assert!(
                    !observation.trace.is_empty(),
                    "{} recorded no observation",
                    contract.row_name(RowKind::Epoll)
                );
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert!(observations.is_empty());
            assert!(!rows.is_empty());
            for row in &rows {
                assert!(
                    matches!(row.verdict, TestVerdict::Skip(_)),
                    "{} must be skipped off Linux, got {:?}",
                    row.test_name,
                    row.verdict
                );
            }
        }
    }

    #[test]
    fn io_uring_rows_pair_with_a_differential_or_are_one_skip() {
        let harness = ReactorConformanceHarness::new();
        #[cfg(all(target_os = "linux", feature = "io-uring"))]
        let epoll = harness.epoll_rows().1;
        #[cfg(not(all(target_os = "linux", feature = "io-uring")))]
        let epoll: Vec<(Contract, Observation)> = Vec::new();
        let rows = harness.io_uring_rows(&epoll);
        if rows.len() == 1 {
            assert_eq!(rows[0].test_name, "io_uring/backend_available");
            assert!(
                matches!(rows[0].verdict, TestVerdict::Skip(_)),
                "an absent io_uring backend must be reported as Skip, never Pass: {:?}",
                rows[0].verdict
            );
            eprintln!("io_uring rows did not run: {:?}", rows[0].verdict);
        } else {
            assert_eq!(rows.len(), 2 * Contract::ALL.len());
            for contract in Contract::ALL {
                for kind in [RowKind::IoUring, RowKind::IoUringVsEpoll] {
                    assert!(
                        rows.iter().any(|row| row.test_name == contract.row_name(kind)),
                        "missing row {}",
                        contract.row_name(kind)
                    );
                }
            }
            assert_gaps_are_tracked(&rows);
            let failures: Vec<(&str, &TestVerdict)> = rows
                .iter()
                .filter(|row| row.is_hard_failure())
                .map(|row| (row.test_name, &row.verdict))
                .collect();
            assert!(
                failures.is_empty(),
                "io_uring contract or differential failures: {failures:#?}"
            );
        }
        #[cfg(not(all(target_os = "linux", feature = "io-uring")))]
        assert_eq!(
            rows.len(),
            1,
            "without a compiled io_uring backend only the availability row may exist"
        );
    }

    #[test]
    fn lab_rows_cover_exactly_the_contracts_lab_can_express() {
        let rows = ReactorConformanceHarness::new().lab_rows();
        #[cfg(any(unix, windows))]
        {
            let names: Vec<&str> = rows.iter().map(|row| row.test_name).collect();
            let expected: Vec<&str> = Contract::ALL
                .iter()
                .filter(|contract| contract.lab_applies())
                .map(|contract| contract.row_name(RowKind::Lab))
                .collect();
            assert_eq!(names, expected);
            for row in &rows {
                assert_eq!(
                    row.verdict,
                    TestVerdict::Pass,
                    "{}: {:?}",
                    row.test_name,
                    row.verdict
                );
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            for row in &rows {
                assert!(matches!(row.verdict, TestVerdict::Skip(_)));
            }
        }
    }

    #[test]
    fn probe_and_gap_controls_fail_when_they_must() {
        // asupersync-ubwvb0 is closed: the edge-triggered contract tolerates
        // no gap on any backend, so its io_uring rows are strict.
        for kind in [
            RowKind::Epoll,
            RowKind::IoUring,
            RowKind::IoUringVsEpoll,
            RowKind::Lab,
        ] {
            assert_eq!(
                known_gap(Contract::EdgeTriggeredRedeliversAfterDrain, kind),
                None,
                "the edge-triggered contract must not tolerate a gap on {kind:?}"
            );
        }

        // The differential reports a tracked gap only for differences that
        // the gap explains, on its own contract, with no other violation.
        let contract = Contract::RegisterWhilePollBlocked;
        let gap = known_gap(contract, RowKind::IoUring).expect("the register gap is tracked");
        assert_eq!(known_gap(contract, RowKind::Epoll), None);
        assert_eq!(known_gap(contract, RowKind::Lab), None);
        let registered = "register while another thread is blocked in poll(None): Ok";
        let stalled = "register while another thread is blocked in poll(None): stalled until \
                       wake(), then Ok";
        let conforming = || {
            let mut observation = Observation::default();
            observation.note(registered);
            observation.note("readiness delivered: yes");
            observation
        };
        let epoll = conforming();
        assert_eq!(
            differential_verdict(contract, Some(&epoll), &conforming()),
            TestVerdict::Pass
        );

        let mut gapped = Observation::default();
        gapped.gap_note(gap, stalled);
        gapped.note("readiness delivered: yes");
        assert_eq!(gapped.verdict(), TestVerdict::ExpectedGap(gap.to_owned()));
        assert_eq!(
            differential_verdict(contract, Some(&epoll), &gapped),
            TestVerdict::ExpectedGap(gap.to_owned())
        );
        assert!(
            matches!(
                differential_verdict(Contract::ReadableAfterPeerWrite, Some(&epoll), &gapped),
                TestVerdict::Fail(_)
            ),
            "a gap is tracked only for its own contract"
        );
        assert!(
            matches!(
                differential_verdict(contract, None, &gapped),
                TestVerdict::Fail(_)
            ),
            "a differential without an epoll observation must fail"
        );

        let mut unexplained = Observation::default();
        unexplained.gap_note(gap, stalled);
        unexplained.note("readiness delivered: no");
        assert!(
            matches!(
                differential_verdict(contract, Some(&epoll), &unexplained),
                TestVerdict::Fail(_)
            ),
            "a difference outside the gap lines must fail"
        );

        let mut misaligned = Observation::default();
        misaligned.gap_note(gap, stalled);
        misaligned.note("readiness delivered: yes");
        misaligned.note("one line more than epoll");
        assert!(
            matches!(
                differential_verdict(contract, Some(&epoll), &misaligned),
                TestVerdict::Fail(_)
            ),
            "traces of different length must fail"
        );

        let mut gapped_and_broken = Observation::default();
        gapped_and_broken.gap_note(gap, stalled);
        gapped_and_broken.note("readiness delivered: yes");
        gapped_and_broken.violation("an unrelated deviation");
        assert!(matches!(gapped_and_broken.verdict(), TestVerdict::Fail(_)));
        assert!(
            matches!(
                differential_verdict(contract, Some(&epoll), &gapped_and_broken),
                TestVerdict::Fail(_)
            ),
            "the gap plus any other violation is not the tracked gap"
        );

        let mut closed = conforming();
        closed.gap_closed_remark(Some(gap), "control");
        assert_eq!(closed.verdict(), TestVerdict::Pass);
        assert_eq!(closed.remarks.len(), 1, "a gap that no longer reproduces is remarked");

        #[cfg(any(unix, windows))]
        {
            // A partitioned lab token drops injected readiness (lab.rs:843-852),
            // so the delivery probe must fail; after healing it must pass.
            let lab = Arc::new(LabReactor::new());
            let source = lab_checks::naming_source().expect("lab naming source");
            let r: &dyn Reactor = &*lab;
            let token = Token::new(9_001);
            r.register(&*source, token, Interest::READABLE)
                .expect("lab register");
            lab.partition(token, true).expect("partition");
            lab.set_ready(token, Event::readable(token));
            let mut events = Events::with_capacity(4);
            let mut dropped = Observation::default();
            let seen = poll_once(r, &mut events, Some(Duration::ZERO), &mut dropped)
                .expect("lab poll");
            assert!(delivered(&mut dropped, "partitioned", &seen, token).is_none());
            assert!(
                matches!(dropped.verdict(), TestVerdict::Fail(_)),
                "a dropped event must fail the probe, got {:?}",
                dropped.verdict()
            );
            lab.partition(token, false).expect("heal the partition");
            lab.set_ready(token, Event::readable(token));
            let mut healed = Observation::default();
            let seen = poll_once(r, &mut events, Some(Duration::ZERO), &mut healed)
                .expect("lab poll");
            assert!(
                delivered(&mut healed, "healed", &seen, token)
                    .is_some_and(|ready| ready.is_readable())
            );
            assert_eq!(healed.verdict(), TestVerdict::Pass);
            r.deregister(token).expect("lab deregister");
        }
        #[cfg(target_os = "linux")]
        {
            kernel_checks::invalid_descriptor_judge_controls();
            kernel_checks::probe_controls();
        }
    }
}
