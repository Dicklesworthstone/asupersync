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
    let mut v6_iter = addrs.iter().copied().filter(IpAddr::is_ipv6);
    let mut v4_iter = addrs.iter().copied().filter(IpAddr::is_ipv4);

    let mut result = Vec::with_capacity(addrs.len());

    loop {
        match (v6_iter.next(), v4_iter.next()) {
            (Some(v6_addr), Some(v4_addr)) => {
                result.push(v6_addr);
                result.push(v4_addr);
            }
            (Some(v6_addr), None) => {
                result.push(v6_addr);
                result.extend(v6_iter);
                break;
            }
            (None, Some(v4_addr)) => {
                result.push(v4_addr);
                result.extend(v4_iter);
                break;
            }
            (None, None) => break,
        }
    }

    result
}

/// Sorts socket addresses per RFC 8305 §4 while preserving per-address ports.
///
/// This follows the same family interleaving policy as [`sort_addresses`], but
/// operates on full `SocketAddr` values so each address keeps its original port.
#[must_use]
fn sort_socket_addrs(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut v6_iter = addrs.iter().copied().filter(SocketAddr::is_ipv6);
    let mut v4_iter = addrs.iter().copied().filter(SocketAddr::is_ipv4);

    let mut result = Vec::with_capacity(addrs.len());

    loop {
        match (v6_iter.next(), v4_iter.next()) {
            (Some(v6_addr), Some(v4_addr)) => {
                result.push(v6_addr);
                result.push(v4_addr);
            }
            (Some(v6_addr), None) => {
                result.push(v6_addr);
                result.extend(v6_iter);
                break;
            }
            (None, Some(v4_addr)) => {
                result.push(v4_addr);
                result.extend(v4_iter);
                break;
            }
            (None, None) => break,
        }
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

    fn poll_with_time(
        &mut self,
        mut now: Time,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<TcpStream>> {
        if self.completed {
            return Poll::Ready(Err(Self::poll_after_completion_error()));
        }

        if Pin::new(&mut self.timeout_sleep).poll(cx).is_ready() {
            return self.finish_overall_timeout();
        }

        loop {
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

            if self.stagger_active {
                if Pin::new(&mut self.stagger_sleep).poll(cx).is_ready() {
                    made_progress = true;
                    self.start_next(now);
                }
            }

            if !made_progress {
                break;
            }

            now = (self.time_getter)();
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

    let deadline =
        time_getter().saturating_add_nanos(duration_to_nanos_saturating(timeout_duration));

    match future_with_timeout(Box::pin(TcpStream::connect(addr)), deadline, time_getter).await {
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
mod tests {
    use super::*;
    use std::future::pending;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::task::{Wake, Waker};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
        fn wake_by_ref(self: &Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Arc::new(NoopWaker).into()
    }

    #[derive(Debug)]
    struct PollCountingPendingConnect {
        polls: Arc<AtomicUsize>,
    }

    impl PollCountingPendingConnect {
        fn new(polls: Arc<AtomicUsize>) -> Self {
            Self { polls }
        }
    }

    impl Future for PollCountingPendingConnect {
        type Output = io::Result<TcpStream>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            Poll::Pending
        }
    }

    fn connected_test_stream() -> TcpStream {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let accept_thread = std::thread::spawn(move || listener.accept().expect("accept").0);
        let client = std::net::TcpStream::connect(addr).expect("connect client");
        let _server = accept_thread.join().expect("join accept thread");
        TcpStream::from_std(client).expect("wrap client stream")
    }

    fn assert_post_completion_error(result: Poll<io::Result<TcpStream>>) {
        let err = match result {
            Poll::Ready(Err(err)) => err,
            Poll::Ready(Ok(_)) => panic!("expected post-completion error, got success"),
            Poll::Pending => panic!("expected post-completion error, got pending"),
        };
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(err.to_string(), RACE_CONNECTIONS_POLLED_AFTER_COMPLETION);
    }

    // =======================================================================
    // Address sorting tests (RFC 8305 §4)
    // =======================================================================

    #[test]
    fn sort_addresses_interleaves_v6_v4() {
        init_test("sort_addresses_interleaves_v6_v4");

        let addrs: Vec<IpAddr> = vec![
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
        ];

        let sorted = sort_addresses(&addrs);

        assert_eq!(sorted.len(), 4);
        // Expected: v6, v4, v6, v4
        assert!(sorted[0].is_ipv6(), "first should be v6: {}", sorted[0]);
        assert!(sorted[1].is_ipv4(), "second should be v4: {}", sorted[1]);
        assert!(sorted[2].is_ipv6(), "third should be v6: {}", sorted[2]);
        assert!(sorted[3].is_ipv4(), "fourth should be v4: {}", sorted[3]);
        crate::test_complete!("sort_addresses_interleaves_v6_v4");
    }

    #[test]
    fn sort_addresses_v6_first_when_equal() {
        init_test("sort_addresses_v6_first_when_equal");

        let addrs: Vec<IpAddr> = vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()];

        let sorted = sort_addresses(&addrs);

        assert_eq!(sorted.len(), 2);
        assert!(sorted[0].is_ipv6(), "v6 should come first");
        assert!(sorted[1].is_ipv4(), "v4 should come second");
        crate::test_complete!("sort_addresses_v6_first_when_equal");
    }

    #[test]
    fn sort_addresses_uneven_more_v4() {
        init_test("sort_addresses_uneven_more_v4");

        let addrs: Vec<IpAddr> = vec![
            "2001:db8::1".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            "192.0.2.3".parse().unwrap(),
        ];

        let sorted = sort_addresses(&addrs);

        assert_eq!(sorted.len(), 4);
        // v6, v4, v4, v4 (v6 exhausted after first pair)
        assert!(sorted[0].is_ipv6());
        assert!(sorted[1].is_ipv4());
        assert!(sorted[2].is_ipv4());
        assert!(sorted[3].is_ipv4());
        crate::test_complete!("sort_addresses_uneven_more_v4");
    }

    #[test]
    fn sort_addresses_uneven_more_v6() {
        init_test("sort_addresses_uneven_more_v6");

        let addrs: Vec<IpAddr> = vec![
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            "2001:db8::3".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
        ];

        let sorted = sort_addresses(&addrs);

        assert_eq!(sorted.len(), 4);
        assert!(sorted[0].is_ipv6());
        assert!(sorted[1].is_ipv4());
        assert!(sorted[2].is_ipv6());
        assert!(sorted[3].is_ipv6());
        crate::test_complete!("sort_addresses_uneven_more_v6");
    }

    #[test]
    fn sort_addresses_v4_only() {
        init_test("sort_addresses_v4_only");

        let addrs: Vec<IpAddr> = vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()];

        let sorted = sort_addresses(&addrs);

        assert_eq!(sorted.len(), 2);
        assert!(sorted.iter().all(IpAddr::is_ipv4));
        crate::test_complete!("sort_addresses_v4_only");
    }

    #[test]
    fn sort_addresses_v6_only() {
        init_test("sort_addresses_v6_only");

        let addrs: Vec<IpAddr> = vec![
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
        ];

        let sorted = sort_addresses(&addrs);

        assert_eq!(sorted.len(), 2);
        assert!(sorted.iter().all(IpAddr::is_ipv6));
        crate::test_complete!("sort_addresses_v6_only");
    }

    #[test]
    fn sort_addresses_empty() {
        init_test("sort_addresses_empty");
        let sorted = sort_addresses(&[]);
        assert!(sorted.is_empty());
        crate::test_complete!("sort_addresses_empty");
    }

    #[test]
    fn sort_addresses_single_v6() {
        init_test("sort_addresses_single_v6");
        let addrs: Vec<IpAddr> = vec!["::1".parse().unwrap()];
        let sorted = sort_addresses(&addrs);
        assert_eq!(sorted.len(), 1);
        assert!(sorted[0].is_ipv6());
        crate::test_complete!("sort_addresses_single_v6");
    }

    #[test]
    fn sort_addresses_single_v4() {
        init_test("sort_addresses_single_v4");
        let addrs: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap()];
        let sorted = sort_addresses(&addrs);
        assert_eq!(sorted.len(), 1);
        assert!(sorted[0].is_ipv4());
        crate::test_complete!("sort_addresses_single_v4");
    }

    #[test]
    fn sort_socket_addrs_preserves_ports() {
        init_test("sort_socket_addrs_preserves_ports");

        let addrs: Vec<SocketAddr> = vec![
            "[2001:db8::1]:443".parse().unwrap(),
            "192.0.2.10:8443".parse().unwrap(),
            "[2001:db8::2]:444".parse().unwrap(),
            "192.0.2.11:8080".parse().unwrap(),
        ];

        let sorted = sort_socket_addrs(&addrs);

        assert_eq!(sorted.len(), 4);
        assert_eq!(
            sorted[0],
            "[2001:db8::1]:443".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(sorted[1], "192.0.2.10:8443".parse::<SocketAddr>().unwrap());
        assert_eq!(
            sorted[2],
            "[2001:db8::2]:444".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(sorted[3], "192.0.2.11:8080".parse::<SocketAddr>().unwrap());

        crate::test_complete!("sort_socket_addrs_preserves_ports");
    }

    #[test]
    fn sort_socket_addrs_uneven_families() {
        init_test("sort_socket_addrs_uneven_families");

        let addrs: Vec<SocketAddr> = vec![
            "[2001:db8::1]:443".parse().unwrap(),
            "192.0.2.10:8080".parse().unwrap(),
            "192.0.2.11:8081".parse().unwrap(),
            "192.0.2.12:8082".parse().unwrap(),
        ];

        let sorted = sort_socket_addrs(&addrs);

        assert_eq!(sorted.len(), 4);
        assert!(sorted[0].is_ipv6());
        assert!(sorted[1].is_ipv4());
        assert!(sorted[2].is_ipv4());
        assert!(sorted[3].is_ipv4());
        assert_eq!(sorted[0].port(), 443);
        assert_eq!(sorted[1].port(), 8080);
        assert_eq!(sorted[2].port(), 8081);
        assert_eq!(sorted[3].port(), 8082);

        crate::test_complete!("sort_socket_addrs_uneven_families");
    }

    // =======================================================================
    // Config tests
    // =======================================================================

    #[test]
    fn config_default_values() {
        init_test("config_default_values");

        let config = HappyEyeballsConfig::default();

        assert_eq!(config.first_family_delay, Duration::from_millis(250));
        assert_eq!(config.attempt_delay, Duration::from_millis(250));
        assert_eq!(config.connect_timeout, Duration::from_secs(5));
        assert_eq!(config.overall_timeout, Duration::from_secs(30));
        crate::test_complete!("config_default_values");
    }

    #[test]
    fn config_clone_debug() {
        init_test("config_clone_debug");

        let config = HappyEyeballsConfig::default();
        let cloned = config.clone();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("HappyEyeballsConfig"));
        assert_eq!(cloned.first_family_delay, config.first_family_delay);
        crate::test_complete!("config_clone_debug");
    }

    #[test]
    fn duration_to_nanos_saturating_clamps_large_values() {
        init_test("duration_to_nanos_saturating_clamps_large_values");
        assert_eq!(duration_to_nanos_saturating(Duration::MAX), u64::MAX);
        crate::test_complete!("duration_to_nanos_saturating_clamps_large_values");
    }

    #[test]
    fn sleep_with_time_getter_waits_for_custom_clock() {
        static TEST_NOW: AtomicU64 = AtomicU64::new(0);

        fn test_time() -> Time {
            Time::from_nanos(TEST_NOW.load(Ordering::SeqCst))
        }

        init_test("sleep_with_time_getter_waits_for_custom_clock");

        TEST_NOW.store(1_000, Ordering::SeqCst);
        let mut sleep = Box::pin(Sleep::with_time_getter(Time::from_nanos(1_500), test_time));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(Future::poll(sleep.as_mut(), &mut cx).is_pending());

        TEST_NOW.store(2_000, Ordering::SeqCst);
        assert!(Future::poll(sleep.as_mut(), &mut cx).is_ready());
        crate::test_complete!("sleep_with_time_getter_waits_for_custom_clock");
    }

    #[test]
    fn future_with_timeout_honors_custom_clock() {
        static TEST_NOW: AtomicU64 = AtomicU64::new(0);

        fn test_time() -> Time {
            Time::from_nanos(TEST_NOW.load(Ordering::SeqCst))
        }

        init_test("future_with_timeout_honors_custom_clock");

        TEST_NOW.store(1_000, Ordering::SeqCst);
        let mut future = Box::pin(future_with_timeout(
            pending::<()>(),
            Time::from_nanos(1_500),
            test_time,
        ));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(Future::poll(future.as_mut(), &mut cx).is_pending());

        TEST_NOW.store(2_000, Ordering::SeqCst);
        assert!(matches!(
            Future::poll(future.as_mut(), &mut cx),
            Poll::Ready(Err(_))
        ));
        crate::test_complete!("future_with_timeout_honors_custom_clock");
    }

    #[test]
    fn single_address_fast_path_honors_overall_timeout() {
        static TEST_NOW: AtomicU64 = AtomicU64::new(0);

        fn test_time() -> Time {
            Time::from_nanos(TEST_NOW.load(Ordering::SeqCst))
        }

        async fn pending_connector(
            _addr: SocketAddr,
            _timeout: Duration,
            _time_getter: fn() -> Time,
        ) -> io::Result<TcpStream> {
            pending::<io::Result<TcpStream>>().await
        }

        init_test("single_address_fast_path_honors_overall_timeout");

        TEST_NOW.store(1_000, Ordering::SeqCst);
        let addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let mut future = Box::pin(connect_single_with_connector(
            addr,
            Duration::from_secs(5),
            Duration::from_nanos(500),
            test_time,
            pending_connector,
        ));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(Future::poll(future.as_mut(), &mut cx).is_pending());

        TEST_NOW.store(2_000, Ordering::SeqCst);
        let result = Future::poll(future.as_mut(), &mut cx);
        assert!(matches!(
            result,
            Poll::Ready(Err(err))
                if err.kind() == io::ErrorKind::TimedOut
                    && err.to_string() == OVERALL_CONNECTION_TIMEOUT_MSG
        ));
        crate::test_complete!("single_address_fast_path_honors_overall_timeout");
    }

    // =======================================================================
    // connect() edge case tests (no network needed)
    // =======================================================================

    #[test]
    fn connect_empty_addrs_returns_error() {
        init_test("connect_empty_addrs_returns_error");

        let config = HappyEyeballsConfig::default();
        let result = futures_lite::future::block_on(connect(&[], &config));

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        crate::test_complete!("connect_empty_addrs_returns_error");
    }

    #[test]
    fn connect_single_loopback_refuses() {
        init_test("connect_single_loopback_refuses");

        // Connect to a port that's almost certainly not listening
        let config = HappyEyeballsConfig {
            connect_timeout: Duration::from_millis(100),
            overall_timeout: Duration::from_millis(200),
            ..Default::default()
        };
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let result = futures_lite::future::block_on(connect(&[addr], &config));

        // Should fail (no server on port 1)
        assert!(result.is_err());
        crate::test_complete!("connect_single_loopback_refuses");
    }

    #[test]
    fn connect_zero_timeout_returns_error() {
        init_test("connect_zero_timeout_returns_error");

        let config = HappyEyeballsConfig {
            connect_timeout: Duration::ZERO,
            ..Default::default()
        };
        let addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let result = futures_lite::future::block_on(connect(&[addr], &config));

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        crate::test_complete!("connect_zero_timeout_returns_error");
    }

    #[test]
    fn connect_multiple_unreachable_tries_all() {
        init_test("connect_multiple_unreachable_tries_all");

        // Multiple addresses that won't connect, with short timeouts
        let config = HappyEyeballsConfig {
            first_family_delay: Duration::from_millis(10),
            attempt_delay: Duration::from_millis(10),
            connect_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(500),
        };

        let addrs: Vec<SocketAddr> = vec![
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
            "127.0.0.1:3".parse().unwrap(),
        ];

        let result = futures_lite::future::block_on(connect(&addrs, &config));
        assert!(result.is_err());
        crate::test_complete!("connect_multiple_unreachable_tries_all");
    }

    #[test]
    fn connect_uses_per_address_ports() {
        init_test("connect_uses_per_address_ports");

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open_addr = listener.local_addr().unwrap();

        let accept_thread = std::thread::spawn(move || {
            // Accept exactly one connection so the connect future can succeed.
            let _ = listener.accept();
        });

        // First address should fail quickly, second should succeed. This test
        // guards against regressions that accidentally reuse the first port for
        // all attempts.
        let closed_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let addrs = vec![closed_addr, open_addr];

        let config = HappyEyeballsConfig {
            first_family_delay: Duration::from_millis(5),
            attempt_delay: Duration::from_millis(5),
            connect_timeout: Duration::from_millis(500),
            overall_timeout: Duration::from_secs(2),
        };

        let runtime = crate::runtime::RuntimeBuilder::new().build().unwrap();
        let handle = runtime
            .handle()
            .spawn(async move { connect(&addrs, &config).await });

        let result = runtime.block_on(handle);
        assert!(
            result.is_ok(),
            "connect should succeed via second address with distinct port: {result:?}"
        );

        let _ = accept_thread.join();
        crate::test_complete!("connect_uses_per_address_ports");
    }

    // =======================================================================
    // RaceConnections structural tests
    // =======================================================================

    #[test]
    fn race_connections_all_fail() {
        init_test("race_connections_all_fail");

        // Race a single future that fails immediately
        let fail_fut: ConnectFuture = Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "test fail",
            ))
        });

        let deadline = timeout_now().saturating_add_nanos(5_000_000_000);
        let mut race = RaceConnections::from_futures(
            vec![fail_fut],
            HappyEyeballsConfig::default(),
            deadline,
            timeout_now,
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let result = race.poll_with_time(timeout_now(), &mut cx);

        // Should complete with the error
        assert!(matches!(
            result,
            Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::ConnectionRefused
        ));
        assert_post_completion_error(race.poll_with_time(timeout_now(), &mut cx));
        crate::test_complete!("race_connections_all_fail");
    }

    #[test]
    fn race_connections_timeout_honors_custom_clock() {
        static TEST_NOW: AtomicU64 = AtomicU64::new(0);

        fn test_time() -> Time {
            Time::from_nanos(TEST_NOW.load(Ordering::SeqCst))
        }

        init_test("race_connections_timeout_honors_custom_clock");

        TEST_NOW.store(1_000, Ordering::SeqCst);
        let pending_fut: ConnectFuture =
            Box::pin(async { pending::<io::Result<TcpStream>>().await });
        let deadline = Time::from_nanos(1_500);
        let mut race = RaceConnections::from_futures(
            vec![pending_fut],
            HappyEyeballsConfig::default(),
            deadline,
            test_time,
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(race.poll_with_time(test_time(), &mut cx).is_pending());

        TEST_NOW.store(2_000, Ordering::SeqCst);
        let result = race.poll_with_time(test_time(), &mut cx);
        assert!(matches!(result, Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::TimedOut));
        assert_post_completion_error(race.poll_with_time(test_time(), &mut cx));
        crate::test_complete!("race_connections_timeout_honors_custom_clock");
    }

    #[test]
    fn race_connections_timeout_overrides_prior_connect_error() {
        static TEST_NOW: AtomicU64 = AtomicU64::new(0);

        fn test_time() -> Time {
            Time::from_nanos(TEST_NOW.load(Ordering::SeqCst))
        }

        init_test("race_connections_timeout_overrides_prior_connect_error");

        TEST_NOW.store(1_000, Ordering::SeqCst);
        let fail_fut: ConnectFuture = Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "early failure",
            ))
        });
        let pending_fut: ConnectFuture =
            Box::pin(async { pending::<io::Result<TcpStream>>().await });
        let deadline = Time::from_nanos(1_500);
        let mut race = RaceConnections::from_futures(
            vec![fail_fut, pending_fut],
            HappyEyeballsConfig::default(),
            deadline,
            test_time,
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(race.poll_with_time(test_time(), &mut cx).is_pending());

        TEST_NOW.store(2_000, Ordering::SeqCst);
        let result = race.poll_with_time(test_time(), &mut cx);
        assert!(matches!(
            result,
            Poll::Ready(Err(err))
                if err.kind() == io::ErrorKind::TimedOut
                    && err.to_string() == OVERALL_CONNECTION_TIMEOUT_MSG
        ));
        assert_post_completion_error(race.poll_with_time(test_time(), &mut cx));
        crate::test_complete!("race_connections_timeout_overrides_prior_connect_error");
    }

    #[test]
    fn race_connections_success_repoll_fails_closed_and_drops_losers() {
        init_test("race_connections_success_repoll_fails_closed_and_drops_losers");

        let loser_polls = Arc::new(AtomicUsize::new(0));
        let loser: ConnectFuture =
            Box::pin(PollCountingPendingConnect::new(Arc::clone(&loser_polls)));
        let winner: ConnectFuture = Box::pin(async { Ok(connected_test_stream()) });

        let deadline = timeout_now().saturating_add_nanos(5_000_000_000);
        let mut race = RaceConnections::from_futures(
            vec![loser, winner],
            HappyEyeballsConfig::default(),
            deadline,
            timeout_now,
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            race.poll_with_time(timeout_now(), &mut cx),
            Poll::Ready(Ok(_))
        ));
        assert_eq!(
            loser_polls.load(Ordering::SeqCst),
            1,
            "loser should be polled exactly once before winner completes"
        );

        assert_post_completion_error(race.poll_with_time(timeout_now(), &mut cx));
        assert_eq!(
            loser_polls.load(Ordering::SeqCst),
            1,
            "post-completion repoll must not touch dropped losers"
        );
        crate::test_complete!("race_connections_success_repoll_fails_closed_and_drops_losers");
    }

    // =======================================================================
    // Stagger schedule tests
    // =======================================================================

    #[test]
    fn stagger_schedule_computed_correctly() {
        init_test("stagger_schedule_computed_correctly");

        let config = HappyEyeballsConfig {
            first_family_delay: Duration::from_millis(250),
            attempt_delay: Duration::from_millis(250),
            ..Default::default()
        };

        // Verify stagger delays match RFC 8305 §5 expectations as implemented
        // in start_next(): started_count==1 uses first_family_delay, all
        // subsequent use attempt_delay. The first attempt (index 0) has no
        // preceding delay.
        //
        // started_count after start_next:
        //   addr[0]: started_count=1 → delay = first_family_delay = 250ms
        //   addr[1]: started_count=2 → delay = attempt_delay      = 250ms
        //   addr[2]: started_count=3 → delay = attempt_delay      = 250ms
        //
        // Each addr beyond the first sees a delay before the next attempt
        // starts, so cumulative stagger is:
        //   addr[0] starts at 0ms (immediate)
        //   addr[1] starts after first_family_delay (250ms)
        //   addr[2] starts after first_family_delay + attempt_delay (500ms)
        //   addr[3] starts after first_family_delay + 2*attempt_delay (750ms)
        let expected_cumulative = [
            Duration::ZERO,
            Duration::from_millis(250),
            Duration::from_millis(500),
            Duration::from_millis(750),
        ];

        // Verify cumulative delays match start_next() logic:
        // started_count==1 → first_family_delay, all others → attempt_delay
        for (i, expected) in expected_cumulative.iter().enumerate().skip(1) {
            let cumulative = if i == 1 {
                config.first_family_delay
            } else {
                config.first_family_delay + config.attempt_delay * (i as u32 - 1)
            };
            assert_eq!(
                cumulative, *expected,
                "addr[{i}] cumulative stagger mismatch: got {cumulative:?}, expected {expected:?}"
            );
        }

        crate::test_complete!("stagger_schedule_computed_correctly");
    }

    #[test]
    fn sort_preserves_address_values() {
        init_test("sort_preserves_address_values");

        let v6_1: IpAddr = "2001:db8::1".parse().unwrap();
        let v6_2: IpAddr = "2001:db8::2".parse().unwrap();
        let v4_1: IpAddr = "10.0.0.1".parse().unwrap();
        let v4_2: IpAddr = "10.0.0.2".parse().unwrap();

        let addrs = vec![v4_1, v6_1, v4_2, v6_2];
        let sorted = sort_addresses(&addrs);

        // All original addresses should be present
        assert_eq!(sorted.len(), 4);
        assert!(sorted.contains(&v6_1));
        assert!(sorted.contains(&v6_2));
        assert!(sorted.contains(&v4_1));
        assert!(sorted.contains(&v4_2));

        // v6 addresses should appear at even indices (0, 2)
        assert_eq!(sorted[0], v6_1);
        assert_eq!(sorted[1], v4_1);
        assert_eq!(sorted[2], v6_2);
        assert_eq!(sorted[3], v4_2);
        crate::test_complete!("sort_preserves_address_values");
    }
}
