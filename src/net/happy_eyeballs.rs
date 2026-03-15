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
//! Uses `asupersync::time` for deterministic sleep (lab-runtime aware) and
//! `asupersync::combinator::select::SelectAll` for concurrent racing.
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
    let v6: Vec<IpAddr> = addrs.iter().copied().filter(IpAddr::is_ipv6).collect();
    let v4: Vec<IpAddr> = addrs.iter().copied().filter(IpAddr::is_ipv4).collect();

    let mut result = Vec::with_capacity(v6.len() + v4.len());
    let mut v6_iter = v6.into_iter();
    let mut v4_iter = v4.into_iter();

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
    let v6: Vec<SocketAddr> = addrs.iter().copied().filter(SocketAddr::is_ipv6).collect();
    let v4: Vec<SocketAddr> = addrs.iter().copied().filter(SocketAddr::is_ipv4).collect();

    let mut result = Vec::with_capacity(v6.len() + v4.len());
    let mut v6_iter = v6.into_iter();
    let mut v4_iter = v4.into_iter();

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
/// is wrapped in a future that first sleeps until its stagger deadline, then
/// attempts the actual connection with a per-connection timeout.
///
/// All futures are polled concurrently via `SelectAll`, so once the first
/// connection succeeds, the others are dropped.
async fn connect_racing(
    addrs: &[SocketAddr],
    config: &HappyEyeballsConfig,
    time_getter: fn() -> Time,
) -> io::Result<TcpStream> {
    let now = time_getter();

    // Build staggered connection futures.
    //
    // Schedule:
    //   addr[0]: start immediately (t=0)
    //   addr[1]: start at t=first_family_delay (250ms)
    //   addr[2]: start at t=first_family_delay + attempt_delay (500ms)
    //   addr[3]: start at t=first_family_delay + 2*attempt_delay (750ms)
    //   ...
    let mut futures: Vec<ConnectFuture> = Vec::with_capacity(addrs.len());

    for (i, &addr) in addrs.iter().enumerate() {
        let stagger = compute_stagger_delay(config, i);

        let connect_timeout = config.connect_timeout;

        futures.push(Box::pin(staggered_connect(
            now,
            stagger,
            addr,
            connect_timeout,
            time_getter,
        )));
    }

    // Race all futures concurrently via RaceConnections.
    //
    // Unlike SelectAll (which returns on the first Ready regardless of
    // success/failure), RaceConnections continues polling if an attempt
    // errors, only returning on first Ok or when all attempts exhaust.
    let overall_deadline =
        now.saturating_add_nanos(duration_to_nanos_saturating(config.overall_timeout));
    RaceConnections::new(futures, overall_deadline, time_getter).await
}

#[inline]
fn duration_to_nanos_saturating(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

#[inline]
fn compute_stagger_delay(config: &HappyEyeballsConfig, index: usize) -> Duration {
    if index == 0 {
        return Duration::ZERO;
    }
    if index == 1 {
        return config.first_family_delay;
    }

    let steps = u32::try_from(index.saturating_sub(1)).unwrap_or(u32::MAX);
    let tail = config
        .attempt_delay
        .checked_mul(steps)
        .unwrap_or(Duration::MAX);
    config
        .first_family_delay
        .checked_add(tail)
        .unwrap_or(Duration::MAX)
}

/// A boxed, pinned, Send future that yields a `TcpStream` or an I/O error.
type ConnectFuture = Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>>;
const RACE_CONNECTIONS_POLLED_AFTER_COMPLETION: &str =
    "Happy Eyeballs RaceConnections polled after completion";
const OVERALL_CONNECTION_TIMEOUT_MSG: &str = "Happy Eyeballs: overall connection timeout";

/// Future that races multiple connection attempts, returning the first success.
///
/// Unlike `SelectAll` which returns on the first Ready (success or error),
/// this continues polling if a result is an error, waiting for either a success
/// or all attempts to fail.
struct RaceConnections {
    /// Connection futures, set to None once completed.
    futures: Vec<Option<ConnectFuture>>,
    /// Number of futures still pending.
    pending: usize,
    /// Whether this future already returned a terminal outcome.
    completed: bool,
    /// Last error seen (returned if all fail).
    last_error: Option<io::Error>,
    /// Sleep future for overall timeout.
    timeout_sleep: Sleep,
    /// Time source used for timeout decisions.
    time_getter: fn() -> Time,
}

impl RaceConnections {
    fn new(futures: Vec<ConnectFuture>, deadline: Time, time_getter: fn() -> Time) -> Self {
        let pending = futures.len();
        let timeout_sleep = Sleep::with_time_getter(deadline, time_getter);
        Self {
            futures: futures.into_iter().map(Some).collect(),
            pending,
            completed: false,
            last_error: None,
            timeout_sleep,
            time_getter,
        }
    }

    fn poll_after_completion_error() -> io::Error {
        io::Error::other(RACE_CONNECTIONS_POLLED_AFTER_COMPLETION)
    }

    fn finish(&mut self, output: io::Result<TcpStream>) -> Poll<io::Result<TcpStream>> {
        self.completed = true;
        self.pending = 0;
        self.last_error = None;
        for slot in &mut self.futures {
            *slot = None;
        }
        Poll::Ready(output)
    }

    fn poll_with_time(&mut self, now: Time, cx: &mut Context<'_>) -> Poll<io::Result<TcpStream>> {
        if self.completed {
            return Poll::Ready(Err(Self::poll_after_completion_error()));
        }

        // Check overall timeout first
        if self.timeout_sleep.poll_with_time(now).is_ready() {
            let err = self.last_error.take().unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, OVERALL_CONNECTION_TIMEOUT_MSG)
            });
            return self.finish(Err(err));
        }

        // Poll all active futures, collecting results to avoid borrow conflicts
        let mut winner: Option<TcpStream> = None;
        let mut completed: Vec<(usize, Option<io::Error>)> = Vec::new();
        let mut any_pending = false;

        for (i, slot) in self.futures.iter_mut().enumerate() {
            if let Some(fut) = slot.as_mut() {
                match Pin::new(fut).poll(cx) {
                    Poll::Ready(Ok(stream)) => {
                        if winner.is_none() {
                            winner = Some(stream);
                        }
                        completed.push((i, None));
                        break;
                    }
                    Poll::Ready(Err(e)) => {
                        completed.push((i, Some(e)));
                    }
                    Poll::Pending => {
                        any_pending = true;
                    }
                }
            }
        }

        // Process completed futures
        for (i, err) in completed {
            self.futures[i] = None;
            self.pending -= 1;
            if let Some(e) = err {
                self.last_error = Some(e);
            }
        }

        // Return winner if we have one
        if let Some(stream) = winner {
            return self.finish(Ok(stream));
        }

        if !any_pending && self.pending == 0 {
            // All attempts exhausted with no success
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
        let poll = self.as_mut().get_mut().poll_with_time(now, cx);
        if poll.is_pending() {
            let this = self.as_mut().get_mut();
            // Preserve wake registration even when timeout decisions use a
            // manual or virtual clock. If the sleep has actually elapsed,
            // we must return the timeout now, otherwise we will lose the wakeup
            // because Sleep::poll does not register a waker when it returns Ready.
            if Pin::new(&mut this.timeout_sleep).poll(cx).is_ready() {
                let err = this.last_error.take().unwrap_or_else(|| {
                    io::Error::new(io::ErrorKind::TimedOut, OVERALL_CONNECTION_TIMEOUT_MSG)
                });
                return this.finish(Err(err));
            }
        }
        poll
    }
}

/// Connects to a single address after a stagger delay, with a per-connection timeout.
async fn staggered_connect(
    now: Time,
    stagger: Duration,
    addr: SocketAddr,
    connect_timeout: Duration,
    time_getter: fn() -> Time,
) -> io::Result<TcpStream> {
    // Wait for our stagger slot
    if !stagger.is_zero() {
        let deadline = now.saturating_add_nanos(duration_to_nanos_saturating(stagger));
        sleep_until_with_time_getter(deadline, time_getter).await;
    }

    // Attempt connection with timeout
    connect_one(addr, connect_timeout, time_getter).await
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

async fn sleep_until_with_time_getter(deadline: Time, time_getter: fn() -> Time) {
    Sleep::with_time_getter(deadline, time_getter).await;
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
    fn compute_stagger_delay_saturates_on_overflow() {
        init_test("compute_stagger_delay_saturates_on_overflow");

        let config = HappyEyeballsConfig {
            first_family_delay: Duration::MAX,
            attempt_delay: Duration::from_secs(1),
            ..Default::default()
        };

        assert_eq!(compute_stagger_delay(&config, 2), Duration::MAX);
        crate::test_complete!("compute_stagger_delay_saturates_on_overflow");
    }

    #[test]
    fn sleep_until_with_time_getter_waits_for_custom_clock() {
        static TEST_NOW: AtomicU64 = AtomicU64::new(0);

        fn test_time() -> Time {
            Time::from_nanos(TEST_NOW.load(Ordering::SeqCst))
        }

        init_test("sleep_until_with_time_getter_waits_for_custom_clock");

        TEST_NOW.store(1_000, Ordering::SeqCst);
        let mut sleep = Box::pin(sleep_until_with_time_getter(
            Time::from_nanos(1_500),
            test_time,
        ));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(Future::poll(sleep.as_mut(), &mut cx).is_pending());

        TEST_NOW.store(2_000, Ordering::SeqCst);
        assert!(Future::poll(sleep.as_mut(), &mut cx).is_ready());
        crate::test_complete!("sleep_until_with_time_getter_waits_for_custom_clock");
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
        let mut race = RaceConnections::new(vec![fail_fut], deadline, timeout_now);
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
        let mut race = RaceConnections::new(vec![pending_fut], deadline, test_time);
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
    fn race_connections_success_repoll_fails_closed_and_drops_losers() {
        init_test("race_connections_success_repoll_fails_closed_and_drops_losers");

        let loser_polls = Arc::new(AtomicUsize::new(0));
        let loser: ConnectFuture =
            Box::pin(PollCountingPendingConnect::new(Arc::clone(&loser_polls)));
        let winner: ConnectFuture = Box::pin(async { Ok(connected_test_stream()) });

        let deadline = timeout_now().saturating_add_nanos(5_000_000_000);
        let mut race = RaceConnections::new(vec![loser, winner], deadline, timeout_now);
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

        // Verify stagger delays match RFC 8305 §5 expectations:
        // addr[0]: 0ms
        // addr[1]: 250ms (first_family_delay)
        // addr[2]: 500ms (first_family_delay + 1 * attempt_delay)
        // addr[3]: 750ms (first_family_delay + 2 * attempt_delay)
        let expected = [
            Duration::ZERO,
            Duration::from_millis(250),
            Duration::from_millis(500),
            Duration::from_millis(750),
        ];

        for (i, expected_delay) in expected.iter().enumerate() {
            let stagger = compute_stagger_delay(&config, i);
            assert_eq!(
                stagger, *expected_delay,
                "addr[{i}] stagger mismatch: got {stagger:?}, expected {expected_delay:?}"
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
