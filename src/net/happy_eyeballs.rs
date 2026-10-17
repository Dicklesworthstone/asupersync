//! Happy Eyeballs v2 (RFC 8305) concurrent connection algorithm.
//!
//! This module implements the Happy Eyeballs algorithm for racing IPv6 and IPv4
//! connection attempts with staggered starts. IPv6 gets a head start (configurable
//! delay, default 250ms), and the first successful connection wins while losers
//! are dropped.
//!
//! # Cancel Safety
//!
//! All functions in this module are cancel-safe. Dropping a future cancels all
//! in-flight connection attempts. Connection futures spawned on the blocking pool
//! continue to completion but their results are discarded.
//!
//! # Integration
//!
//! Uses `asupersync::time` for deterministic sleep (lab-runtime aware) and an
//! internal state machine to coordinate staggered connection attempts.
//!
//! # References
//!
//! - RFC 8305: Happy Eyeballs Version 2: Better Connectivity Using Concurrency
//! - RFC 6555: Happy Eyeballs -- Success with Dual-Stack Hosts (superseded by 8305)

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::cx::Cx;
use crate::net::TcpStream;
use crate::time::{Sleep, TimeoutFuture};
use crate::types::Time;

/// Configuration for Happy Eyeballs connection racing.
#[derive(Debug, Clone)]
pub struct HappyEyeballsConfig {
    /// Delay before starting the first IPv4 connection attempt (RFC 8305 §8).
    /// The IPv6 address family gets a head start of this duration.
    /// Default: 250ms per RFC 8305 recommendation.
    pub first_family_delay: Duration,

    /// Delay between subsequent connection attempts within the same family.
    /// Default: 250ms.
    pub attempt_delay: Duration,

    /// Per-connection timeout. Each individual connection attempt will be
    /// abandoned if it hasn't completed within this duration.
    /// Default: 5s.
    pub connect_timeout: Duration,

    /// Overall timeout for the entire Happy Eyeballs procedure.
    /// Default: 30s.
    pub overall_timeout: Duration,
}

impl Default for HappyEyeballsConfig {
    fn default() -> Self {
        Self {
            first_family_delay: Duration::from_millis(250),
            attempt_delay: Duration::from_millis(250),
            connect_timeout: Duration::from_secs(5),
            overall_timeout: Duration::from_secs(30),
        }
    }
}

/// Sorts addresses per RFC 8305 §4: interleave address families with IPv6 first.
///
/// Given a mixed list of IPv4 and IPv6 addresses, produces an interleaved ordering:
/// `[v6_0, v4_0, v6_1, v4_1, ...]` with any remaining addresses from the longer
/// family appended at the end.
#[must_use]
pub fn sort_addresses(addrs: &[IpAddr]) -> Vec<IpAddr> {
    let v6_iter = addrs.iter().copied().filter(IpAddr::is_ipv6);
    let v4_iter = addrs.iter().copied().filter(IpAddr::is_ipv4);
    let mut result = Vec::with_capacity(addrs.len());

    extend_interleaved(&mut result, v6_iter, v4_iter);

    result
}

fn extend_interleaved<T>(
    result: &mut Vec<T>,
    mut lead_iter: impl Iterator<Item = T>,
    mut follow_iter: impl Iterator<Item = T>,
) {
    loop {
        match (lead_iter.next(), follow_iter.next()) {
            (Some(lead), Some(follow)) => {
                result.push(lead);
                result.push(follow);
            }
            (Some(lead), None) => {
                result.push(lead);
                result.extend(lead_iter);
                break;
            }
            (None, Some(follow)) => {
                result.push(follow);
                result.extend(follow_iter);
                break;
            }
            (None, None) => break,
        }
    }
}

/// Sorts socket addresses per RFC 8305 §4 while preserving per-address ports.
///
/// This follows the same family interleaving policy as [`sort_addresses`], but
/// operates on full `SocketAddr` values so each address keeps its original port.
/// The first address family in the input keeps the lead position so prior
/// resolver ordering is preserved.
#[must_use]
fn sort_socket_addrs(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let prefer_v6 = addrs.first().is_none_or(SocketAddr::is_ipv6);
    let v6_iter = addrs.iter().copied().filter(SocketAddr::is_ipv6);
    let v4_iter = addrs.iter().copied().filter(SocketAddr::is_ipv4);
    let mut result = Vec::with_capacity(addrs.len());

    if prefer_v6 {
        extend_interleaved(&mut result, v6_iter, v4_iter);
    } else {
        extend_interleaved(&mut result, v4_iter, v6_iter);
    }

    result
}

/// Races connection attempts to a set of addresses using Happy Eyeballs v2.
///
/// The algorithm:
/// 1. Sort addresses by family (IPv6 first, interleaved with IPv4)
/// 2. Start the first connection attempt immediately
/// 3. After `first_family_delay`, start the next attempt
/// 4. Continue staggering attempts at `attempt_delay` intervals
/// 5. Return the first successful connection, dropping all others
///
/// If all attempts fail, returns the error from the last attempted connection.
///
/// # Cancel Safety
///
/// Cancel-safe. Dropping the returned future cancels all pending connection
/// attempts. Blocking pool connections continue but results are discarded.
pub async fn connect(addrs: &[SocketAddr], config: &HappyEyeballsConfig) -> io::Result<TcpStream> {
    connect_with_time_getter(addrs, config, timeout_now).await
}

/// Races connection attempts to a set of addresses using an explicit time source.
pub(crate) async fn connect_with_time_getter(
    addrs: &[SocketAddr],
    config: &HappyEyeballsConfig,
    time_getter: fn() -> Time,
) -> io::Result<TcpStream> {
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no addresses provided for Happy Eyeballs connect",
        ));
    }

    // Single address: skip the racing machinery entirely
    if addrs.len() == 1 {
        return connect_single(addrs[0], config, time_getter).await;
    }

    // Sort addresses: interleave IPv6 and IPv4 while preserving each
    // address's original port.
    let sorted_addrs = sort_socket_addrs(addrs);

    // Race connections with staggered starts
    connect_racing(&sorted_addrs, config, time_getter).await
}

/// Resolves `addr` as [`TcpStream::connect`] does and races the resolved
/// addresses when there are several, so an address that never answers does
/// not hold up the next one (br-asupersync-1aqha7). The HTTP/1, HTTP/2 and
/// WebSocket clients connect to hostnames through this.
///
/// `timeout` bounds each attempt and the race as a whole, but not
/// resolution, the same budget [`TcpStream::connect_timeout`] gives its
/// sequential attempts. Without it only the OS connect limits apply, and a
/// single address is a plain connect.
///
/// The future is boxed: callers nest it in their own setup futures, and the
/// race's full type made proving those futures `Send` overflow the trait
/// solver's recursion limit.
pub(crate) fn connect_resolved<A>(addr: A, timeout: Option<Duration>) -> ConnectFuture
where
    A: std::net::ToSocketAddrs + Send + 'static,
{
    Box::pin(async move {
        let addrs = crate::net::lookup_all(addr).await?;
        if let ([only], None) = (addrs.as_slice(), timeout) {
            return TcpStream::connect(*only).await;
        }
        let limit = timeout.unwrap_or(Duration::MAX);
        let config = HappyEyeballsConfig {
            connect_timeout: limit,
            overall_timeout: limit,
            ..HappyEyeballsConfig::default()
        };
        connect_with_time_getter(&addrs, &config, timeout_now).await
    })
}

async fn connect_single(
    addr: SocketAddr,
    config: &HappyEyeballsConfig,
    time_getter: fn() -> Time,
) -> io::Result<TcpStream> {
    connect_single_with_connector(
        addr,
        config.connect_timeout,
        config.overall_timeout,
        time_getter,
        connect_one,
    )
    .await
}

async fn connect_single_with_connector<Fut, Connector>(
    addr: SocketAddr,
    connect_timeout: Duration,
    overall_timeout: Duration,
    time_getter: fn() -> Time,
    connector: Connector,
) -> io::Result<TcpStream>
where
    Fut: Future<Output = io::Result<TcpStream>> + 'static,
    Connector: FnOnce(SocketAddr, Duration, fn() -> Time) -> Fut,
{
    if overall_timeout.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            OVERALL_CONNECTION_TIMEOUT_MSG,
        ));
    }

    let overall_deadline =
        time_getter().saturating_add_nanos(duration_to_nanos_saturating(overall_timeout));

    match future_with_timeout(
        Box::pin(connector(addr, connect_timeout, time_getter)),
        overall_deadline,
        time_getter,
    )
    .await
    {
        Ok(result) => result,
        Err(_elapsed) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            OVERALL_CONNECTION_TIMEOUT_MSG,
        )),
    }
}

/// Races connection attempts with staggered starts.
///
/// This is the core of the Happy Eyeballs algorithm. Each connection attempt
/// is coordinated by `RaceConnections`, which starts additional attempts on
/// staggered delays while still being able to bypass the remaining delay when
/// an active connection fails early.
async fn connect_racing(
    addrs: &[SocketAddr],
    config: &HappyEyeballsConfig,
    time_getter: fn() -> Time,
) -> io::Result<TcpStream> {
    let now = time_getter();
    let overall_deadline =
        now.saturating_add_nanos(duration_to_nanos_saturating(config.overall_timeout));
    RaceConnections::new(
        addrs.to_vec(),
        config.clone(),
        overall_deadline,
        time_getter,
    )
    .await
}

#[inline]
fn duration_to_nanos_saturating(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// A boxed, pinned, Send future that yields a `TcpStream` or an I/O error.
type ConnectFuture = Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>>;
const RACE_CONNECTIONS_POLLED_AFTER_COMPLETION: &str =
    "Happy Eyeballs RaceConnections polled after completion";
const OVERALL_CONNECTION_TIMEOUT_MSG: &str = "Happy Eyeballs: overall connection timeout";
const CONNECT_CANCELLED_MSG: &str = "Happy Eyeballs: connect cancelled";

/// Whether the task that owns the race has been cancelled, by the check
/// TcpStream::connect applies to its own attempts.
fn owner_cancelled() -> bool {
    Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false)
}

/// Future that races multiple connection attempts, returning the first success.
///
/// Implements RFC 8305: starts connections with staggered delays, but immediately
/// starts the next connection if the current active attempt fails, bypassing the
/// remaining stagger delay.
struct RaceConnections {
    addrs: std::vec::IntoIter<SocketAddr>,
    in_flight: Vec<ConnectFuture>,
    completed: bool,
    last_error: Option<io::Error>,
    stagger_sleep: Sleep,
    timeout_sleep: Sleep,
    time_getter: fn() -> Time,
    config: HappyEyeballsConfig,
    stagger_active: bool,
    started_count: usize,
}

impl RaceConnections {
    fn new(
        addrs: Vec<SocketAddr>,
        config: HappyEyeballsConfig,
        deadline: Time,
        time_getter: fn() -> Time,
    ) -> Self {
        let mut rc = Self {
            addrs: addrs.into_iter(),
            in_flight: Vec::new(),
            completed: false,
            last_error: None,
            // These sleeps must share RaceConnections' logical clock. In
            // tests and lab runs the deadline may be in a virtual epoch, so
            // using wall-clock Sleep::new would make stale wall time expire
            // the race before the supplied time source reaches the deadline.
            stagger_sleep: Sleep::with_time_getter(Time::ZERO, time_getter),
            timeout_sleep: Sleep::with_time_getter(deadline, time_getter),
            time_getter,
            config,
            stagger_active: false,
            started_count: 0,
        };
        rc.start_next(time_getter());
        rc
    }

    /// Test-only constructor that accepts pre-built futures instead of addresses.
    #[cfg(test)]
    fn from_futures(
        futures: Vec<ConnectFuture>,
        config: HappyEyeballsConfig,
        deadline: Time,
        time_getter: fn() -> Time,
    ) -> Self {
        let mut remaining = futures;
        // Start the first future immediately so tests exercise the same
        // "one active attempt at construction" invariant as production.
        let first = if remaining.is_empty() {
            None
        } else {
            Some(remaining.remove(0))
        };
        let mut rc = Self {
            addrs: Vec::new().into_iter(),
            in_flight: Vec::new(),
            completed: false,
            last_error: None,
            stagger_sleep: Sleep::with_time_getter(Time::ZERO, time_getter),
            timeout_sleep: Sleep::with_time_getter(deadline, time_getter),
            time_getter,
            config,
            stagger_active: false,
            started_count: 0,
        };
        if let Some(f) = first {
            rc.in_flight.push(f);
            rc.started_count = 1;
        }
        // Queue remaining futures directly into `in_flight`; structural tests
        // control readiness explicitly and do not need stagger scheduling.
        for f in remaining {
            rc.in_flight.push(f);
            rc.started_count += 1;
        }
        rc
    }

    fn start_next(&mut self, now: Time) {
        if let Some(addr) = self.addrs.next() {
            self.in_flight.push(Box::pin(connect_one(
                addr,
                self.config.connect_timeout,
                self.time_getter,
            )));
            self.started_count += 1;

            if self.addrs.len() > 0 {
                let delay = if self.started_count == 1 {
                    self.config.first_family_delay
                } else {
                    self.config.attempt_delay
                };
                self.stagger_sleep.reset_after(now, delay);
                self.stagger_active = true;
            } else {
                self.stagger_active = false;
            }
        } else {
            self.stagger_active = false;
        }
    }

    fn poll_after_completion_error() -> io::Error {
        io::Error::other(RACE_CONNECTIONS_POLLED_AFTER_COMPLETION)
    }

    fn finish(&mut self, output: io::Result<TcpStream>) -> Poll<io::Result<TcpStream>> {
        self.completed = true;
        self.in_flight.clear();
        self.last_error = None;
        Poll::Ready(output)
    }

    fn finish_overall_timeout(&mut self) -> Poll<io::Result<TcpStream>> {
        self.finish(Err(io::Error::new(
            io::ErrorKind::TimedOut,
            OVERALL_CONNECTION_TIMEOUT_MSG,
        )))
    }

    fn finish_cancelled(&mut self) -> Poll<io::Result<TcpStream>> {
        self.finish(Err(io::Error::new(
            io::ErrorKind::Interrupted,
            CONNECT_CANCELLED_MSG,
        )))
    }

    fn poll_with_time(
        &mut self,
        mut now: Time,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<TcpStream>> {
        if self.completed {
            return Poll::Ready(Err(Self::poll_after_completion_error()));
        }
        // A cancelled owner ends the race as TcpStream::connect does, with
        // Interrupted. Polling on would dial the remaining addresses.
        if owner_cancelled() {
            return self.finish_cancelled();
        }

        loop {
            if self.timeout_sleep.is_elapsed(now) {
                return self.finish_overall_timeout();
            }

            let mut made_progress = false;

            let mut i = 0;
            while i < self.in_flight.len() {
                // We use `.as_mut()` on the pinned in_flight future to poll it.
                if let Poll::Ready(res) = Pin::new(&mut self.in_flight[i]).poll(cx) {
                    made_progress = true;
                    // Remove the completed future. The elements shift left, so we do NOT increment `i`.
                    drop(self.in_flight.remove(i));
                    match res {
                        Ok(stream) => {
                            return self.finish(Ok(stream));
                        }
                        Err(e) => {
                            if e.kind() == io::ErrorKind::Interrupted && owner_cancelled() {
                                return self.finish(Err(e));
                            }
                            self.last_error = Some(e);
                            // If an attempt fails, start the next one immediately (RFC 8305 5.4).
                            if self.addrs.len() > 0 {
                                self.start_next(now);
                            }
                        }
                    }
                } else {
                    i += 1;
                }
            }

            // poll_deadline, not poll: Sleep::poll completes early when its
            // task is cancelled, which would read as an elapsed delay.
            if self.stagger_active {
                if Pin::new(&mut self.stagger_sleep)
                    .poll_deadline(cx)
                    .is_ready()
                {
                    made_progress = true;
                    self.start_next(now);
                }
            }

            if !made_progress {
                break;
            }

            now = (self.time_getter)();
        }

        // A race without an overall limit arms no timer.
        if self.timeout_sleep.deadline() < Time::MAX
            && Pin::new(&mut self.timeout_sleep)
                .poll_deadline(cx)
                .is_ready()
        {
            return self.finish_overall_timeout();
        }

        if self.in_flight.is_empty() && self.addrs.len() == 0 {
            let err = self.last_error.take().unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "Happy Eyeballs: all connection attempts failed",
                )
            });
            return self.finish(Err(err));
        }

        Poll::Pending
    }
}

impl Future for RaceConnections {
    type Output = io::Result<TcpStream>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let now = (self.time_getter)();
        self.as_mut().get_mut().poll_with_time(now, cx)
    }
}

/// Connects to a single address with a timeout.
async fn connect_one(
    addr: SocketAddr,
    timeout_duration: Duration,
    time_getter: fn() -> Time,
) -> io::Result<TcpStream> {
    if timeout_duration.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "zero connect timeout",
        ));
    }

    let attempt = Box::pin(TcpStream::connect(addr));
    // `connect_resolved` without a timeout: no timer for a limit that never
    // expires.
    if timeout_duration == Duration::MAX {
        return attempt.await;
    }
    let deadline =
        time_getter().saturating_add_nanos(duration_to_nanos_saturating(timeout_duration));

    match future_with_timeout(attempt, deadline, time_getter).await {
        Ok(result) => result,
        Err(_elapsed) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("connection to {addr} timed out after {timeout_duration:?}"),
        )),
    }
}

async fn future_with_timeout<F>(
    future: F,
    deadline: Time,
    time_getter: fn() -> Time,
) -> Result<F::Output, crate::time::Elapsed>
where
    F: Future + Unpin,
{
    TimeoutFuture::with_time_getter(future, deadline, time_getter).await
}

/// Gets the current time, preferring the runtime timer driver over wall clock.
fn timeout_now() -> Time {
    if let Some(current) = Cx::current() {
        if let Some(driver) = current.timer_driver() {
            return driver.now();
        }
    }
    // Use wall_now() to match the time base that Sleep::poll() uses when
    // no Cx/timer_driver is available. A separate WallClock would have a
    // different epoch, causing deadline mismatches with sleep().
    crate::time::wall_now()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "happy_eyeballs_inline_tests.rs"]
mod tests;
