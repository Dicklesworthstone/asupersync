//! Async DNS resolver with caching and Happy Eyeballs support.
//!
//! # Cancel Safety
//!
//! - `lookup_ip`: Cancel-safe, DNS query can be cancelled at any point.
//! - `happy_eyeballs_connect`: Cancel-safe, connection attempts are cancelled on drop.
//!
//! # Phase 0 Implementation
//!
//! In Phase 0, DNS resolution uses `std::net::ToSocketAddrs` which performs
//! synchronous resolution. The async API is maintained for forward compatibility
//! with future async DNS implementations.

use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream as StdTcpStream, ToSocketAddrs};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use super::cache::{CacheConfig, CacheStats, DnsCache};
use super::error::DnsError;
use super::lookup::{HappyEyeballs, LookupIp, LookupMx, LookupSrv, LookupTxt};
use crate::net::TcpStream;
use crate::runtime::spawn_blocking::spawn_blocking_on_thread;
use crate::time::{Elapsed, Sleep};
use crate::types::Time;

/// DNS resolver configuration.
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    /// Nameservers to use (empty = use system resolvers).
    ///
    /// Phase 0 lookup implementation uses `std::net::ToSocketAddrs`, so
    /// explicit nameservers are not yet supported and fail closed.
    pub nameservers: Vec<SocketAddr>,
    /// Enable caching.
    pub cache_enabled: bool,
    /// Cache configuration.
    pub cache_config: CacheConfig,
    /// Lookup timeout.
    pub timeout: Duration,
    /// Number of retries.
    pub retries: u32,
    /// Enable Happy Eyeballs (RFC 6555).
    pub happy_eyeballs: bool,
    /// Delay before starting IPv4 connection attempt (Happy Eyeballs).
    pub happy_eyeballs_delay: Duration,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            nameservers: Vec::new(),
            cache_enabled: true,
            cache_config: CacheConfig::default(),
            timeout: Duration::from_secs(5),
            retries: 3,
            happy_eyeballs: true,
            happy_eyeballs_delay: Duration::from_millis(250),
        }
    }
}

impl ResolverConfig {
    /// Creates a resolver config using Google Public DNS (8.8.8.8, 8.8.4.4).
    #[must_use]
    pub fn google() -> Self {
        Self {
            nameservers: vec![
                SocketAddr::from(([8, 8, 8, 8], 53)),
                SocketAddr::from(([8, 8, 4, 4], 53)),
            ],
            ..Default::default()
        }
    }

    /// Creates a resolver config using Cloudflare DNS (1.1.1.1, 1.0.0.1).
    #[must_use]
    pub fn cloudflare() -> Self {
        Self {
            nameservers: vec![
                SocketAddr::from(([1, 1, 1, 1], 53)),
                SocketAddr::from(([1, 0, 0, 1], 53)),
            ],
            ..Default::default()
        }
    }
}

/// Async DNS resolver with caching.
///
/// The resolver provides DNS lookups with configurable caching, retry logic,
/// and Happy Eyeballs (RFC 6555) support for optimal connection establishment.
///
/// # Example
///
/// ```ignore
/// let resolver = Resolver::new();
///
/// // Simple IP lookup
/// let lookup = resolver.lookup_ip("example.com").await?;
/// for addr in lookup.addresses() {
///     println!("{}", addr);
/// }
///
/// // Happy Eyeballs connection
/// let stream = resolver.happy_eyeballs_connect("example.com", 443).await?;
/// ```
#[derive(Debug)]
pub struct Resolver {
    config: ResolverConfig,
    cache: Arc<DnsCache>,
    time_getter: fn() -> Time,
}

impl Resolver {
    /// Creates a new resolver with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(ResolverConfig::default())
    }

    /// Creates a new resolver with custom configuration.
    #[must_use]
    pub fn with_config(config: ResolverConfig) -> Self {
        let cache = Arc::new(DnsCache::with_config(config.cache_config.clone()));
        Self {
            config,
            cache,
            time_getter: crate::time::wall_now,
        }
    }

    /// Creates a new resolver with a custom time source.
    #[must_use]
    pub fn with_time_getter(config: ResolverConfig, time_getter: fn() -> Time) -> Self {
        let cache = Arc::new(DnsCache::with_time_getter(
            config.cache_config.clone(),
            time_getter,
        ));
        Self {
            config,
            cache,
            time_getter,
        }
    }

    /// Returns the time source used for resolver timeout decisions.
    #[must_use]
    pub const fn time_getter(&self) -> fn() -> Time {
        self.time_getter
    }

    fn timeout_future<F>(&self, duration: Duration, future: F) -> ResolverTimeout<F> {
        ResolverTimeout::new(future, duration, self.time_getter)
    }

    /// Looks up IP addresses for a hostname.
    ///
    /// Returns addresses suitable for connecting to the host.
    /// Results are cached according to TTL.
    pub async fn lookup_ip(&self, host: &str) -> Result<LookupIp, DnsError> {
        // Literal IPs do not require resolver selection.
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(LookupIp::new(vec![ip], Duration::from_secs(0)));
        }

        validate_lookup_hostname(host)?;

        if !self.config.nameservers.is_empty() {
            return Err(DnsError::NotImplemented(
                "custom nameservers in Phase 0 resolver",
            ));
        }

        // Preserve absolute-name semantics in the cache: `example.com.` may be
        // resolved differently from `example.com` when the system resolver
        // applies search domains to the non-dotted form.
        // Only validation trims one trailing root dot.
        if self.config.cache_enabled {
            if let Some(cached) = self.cache.get_ip_result(host) {
                return cached;
            }
        }

        let result = self.do_lookup_ip(host).await;

        if self.config.cache_enabled {
            match &result {
                Ok(lookup) => self.cache.put_ip(host, lookup),
                Err(DnsError::NoRecords(_)) => self.cache.put_negative_ip_no_records(host),
                Err(_) => {}
            }
        }

        result
    }

    /// Performs the actual IP lookup with retries.
    ///
    /// # Cancellation Safety
    ///
    /// This function is cancel-safe. If the future is dropped, the underlying
    /// DNS query continues on the blocking pool but the result is discarded.
    async fn do_lookup_ip(&self, host: &str) -> Result<LookupIp, DnsError> {
        validate_lookup_hostname(host)?;

        let retries = self.config.retries;
        if self.config.timeout.is_zero() {
            return Err(DnsError::Timeout);
        }
        let host = host.to_string();

        // Keep DNS resolution off the runtime thread even when a current `Cx`
        // exists without a blocking pool handle.
        let lookup = Box::pin(spawn_blocking_dns(move || {
            let mut last_error = None;

            for _attempt in 0..=retries {
                match Self::query_ip_sync(&host) {
                    Ok(result) => return Ok(result),
                    Err(e) => {
                        if matches!(e, DnsError::NoRecords(_)) {
                            return Err(e);
                        }
                        last_error = Some(e);
                    }
                }
            }

            Err(last_error.unwrap_or(DnsError::Timeout))
        }));

        self.timeout_future(self.config.timeout, lookup)
            .await
            .map_or(Err(DnsError::Timeout), |result| result)
    }

    /// Performs synchronous DNS lookup using std::net.
    fn query_ip_sync(host: &str) -> Result<LookupIp, DnsError> {
        // Use ToSocketAddrs which performs DNS resolution
        let addr_str = format!("{host}:0");

        let addrs: Vec<IpAddr> = addr_str
            .to_socket_addrs()
            .map_err(|err| Self::classify_lookup_io_error(host, &err))?
            .map(|sa| sa.ip())
            .collect();

        if addrs.is_empty() {
            return Err(DnsError::NoRecords(host.to_string()));
        }

        // Default TTL since std::net doesn't provide it
        let ttl = Duration::from_mins(5);

        Ok(LookupIp::new(addrs, ttl))
    }

    fn classify_lookup_io_error(host: &str, err: &io::Error) -> DnsError {
        let message = err.to_string();
        let lower = message.to_ascii_lowercase();

        if lower.contains("name or service not known")
            || lower.contains("nodename nor servname provided, or not known")
            || lower.contains("no address associated with hostname")
            || lower.contains("host not found")
            || lower.contains("no such host")
            || lower.contains("non-existent domain")
        {
            return DnsError::NoRecords(host.to_string());
        }

        DnsError::Io(message)
    }

    /// Looks up IP addresses with Happy Eyeballs ordering.
    ///
    /// Returns addresses interleaved IPv6/IPv4 for optimal connection racing.
    pub async fn lookup_ip_happy(&self, host: &str) -> Result<HappyEyeballs, DnsError> {
        let lookup = self.lookup_ip(host).await?;
        Ok(HappyEyeballs::from_lookup(&lookup))
    }

    /// Connects to a host using Happy Eyeballs (RFC 6555).
    ///
    /// Races IPv6 and IPv4 connection attempts, returning the first successful
    /// connection. IPv6 is preferred with a short head start.
    ///
    /// # Cancel Safety
    ///
    /// If cancelled, all pending connection attempts are aborted.
    pub async fn happy_eyeballs_connect(
        &self,
        host: &str,
        port: u16,
    ) -> Result<TcpStream, DnsError> {
        let lookup = self.lookup_ip(host).await?;
        let addrs = lookup.addresses();

        if addrs.is_empty() {
            return Err(DnsError::NoRecords(host.to_string()));
        }

        // Sort: IPv6 first, then IPv4
        let mut sorted_addrs: Vec<SocketAddr> =
            addrs.iter().map(|ip| SocketAddr::new(*ip, port)).collect();
        sorted_addrs.sort_by_key(|a| i32::from(!a.is_ipv6()));

        // If Happy Eyeballs is disabled, just try sequentially
        if !self.config.happy_eyeballs {
            return self.connect_sequential(&sorted_addrs).await;
        }

        // Happy Eyeballs: race connections with staggered starts
        self.connect_happy_eyeballs(&sorted_addrs).await
    }

    /// Connects sequentially to addresses.
    async fn connect_sequential(&self, addrs: &[SocketAddr]) -> Result<TcpStream, DnsError> {
        let mut last_error = None;

        for addr in addrs {
            match self.try_connect(*addr).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last_error = Some(e),
            }
        }

        Err(last_error
            .unwrap_or_else(|| DnsError::Connection("no addresses to connect to".to_string())))
    }

    /// Connects using Happy Eyeballs v2 (RFC 8305) with concurrent racing.
    ///
    /// Connection attempts are started with staggered delays and raced
    /// concurrently. The first successful connection wins; all others are
    /// dropped. This replaces the previous sequential stagger implementation.
    fn classify_connect_error(err: &io::Error) -> DnsError {
        match err.kind() {
            io::ErrorKind::TimedOut => DnsError::Timeout,
            _ => DnsError::Connection(err.to_string()),
        }
    }

    async fn connect_happy_eyeballs(&self, addrs: &[SocketAddr]) -> Result<TcpStream, DnsError> {
        use crate::net::happy_eyeballs::{self, HappyEyeballsConfig};

        let config = HappyEyeballsConfig {
            first_family_delay: self.config.happy_eyeballs_delay,
            attempt_delay: self.config.happy_eyeballs_delay,
            connect_timeout: self.config.timeout,
            overall_timeout: self.config.timeout.saturating_mul(2).saturating_add(
                self.config
                    .happy_eyeballs_delay
                    .saturating_mul(u32::try_from(addrs.len()).unwrap_or(u32::MAX)),
            ),
        };

        happy_eyeballs::connect_with_time_getter(addrs, &config, self.time_getter)
            .await
            .map_err(|err| Self::classify_connect_error(&err))
    }

    /// Attempts to connect to a single address.
    async fn try_connect(&self, addr: SocketAddr) -> Result<TcpStream, DnsError> {
        self.try_connect_timeout(addr, self.config.timeout).await
    }

    /// Attempts to connect with a timeout.
    ///
    /// # Cancellation Safety
    ///
    /// This function is cancel-safe. If the future is dropped, the underlying
    /// connection attempt continues on the blocking pool but the result is discarded.
    async fn try_connect_timeout(
        &self,
        addr: SocketAddr,
        timeout_duration: Duration,
    ) -> Result<TcpStream, DnsError> {
        if timeout_duration.is_zero() {
            return Err(DnsError::Timeout);
        }

        // Keep blocking connect off the runtime thread even when a current
        // `Cx` exists without a blocking pool handle.
        let connect = Box::pin(spawn_blocking_dns(move || {
            let stream =
                StdTcpStream::connect(addr).map_err(|e| DnsError::Connection(e.to_string()))?;

            stream
                .set_nonblocking(true)
                .map_err(|e| DnsError::Io(e.to_string()))?;

            Ok::<_, DnsError>(stream)
        }));

        let result = self
            .timeout_future(timeout_duration, connect)
            .await
            .map_or(Err(DnsError::Timeout), |result| result)?;

        // ubs:ignore — TcpStream returned to caller; caller owns shutdown lifecycle
        TcpStream::from_std(result).map_err(|e| DnsError::Io(e.to_string()))
    }

    /// Looks up MX records for a domain.
    pub async fn lookup_mx(&self, _domain: &str) -> Result<LookupMx, DnsError> {
        // Phase 0: MX lookup not implemented
        // Would require trust-dns or similar for proper DNS record queries
        Err(DnsError::NotImplemented("MX lookup"))
    }

    /// Looks up SRV records.
    pub async fn lookup_srv(&self, _name: &str) -> Result<LookupSrv, DnsError> {
        Err(DnsError::NotImplemented("SRV lookup"))
    }

    /// Looks up TXT records.
    pub async fn lookup_txt(&self, _name: &str) -> Result<LookupTxt, DnsError> {
        Err(DnsError::NotImplemented("TXT lookup"))
    }

    /// Clears the DNS cache.
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Evicts expired entries from the cache.
    pub fn evict_expired(&self) {
        self.cache.evict_expired();
    }

    /// Returns cache statistics.
    #[must_use]
    pub fn cache_stats(&self) -> CacheStats {
        self.cache.stats()
    }
}

impl Default for Resolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Resolver {
    fn clone(&self) -> Self {
        // Share the cache across clones
        Self {
            config: self.config.clone(),
            cache: Arc::clone(&self.cache),
            time_getter: self.time_getter,
        }
    }
}

fn duration_to_nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

fn timeout_now() -> Time {
    crate::cx::Cx::current()
        .and_then(|current| current.timer_driver())
        .map_or_else(crate::time::wall_now, |driver| driver.now())
}

#[derive(Debug)]
struct ResolverTimeout<F> {
    future: F,
    deadline: Time,
    sleep: Sleep,
    time_getter: fn() -> Time,
    completed: bool,
}

impl<F> ResolverTimeout<F> {
    fn new(future: F, duration: Duration, time_getter: fn() -> Time) -> Self {
        let deadline = time_getter().saturating_add_nanos(duration_to_nanos(duration));
        let wake_deadline = timeout_now().saturating_add_nanos(duration_to_nanos(duration));
        Self {
            future,
            deadline,
            // Use a wake-capable sleep in the runtime/wall-clock time domain,
            // but keep `deadline` authoritative for timeout decisions.
            sleep: Sleep::new(wake_deadline),
            time_getter,
            completed: false,
        }
    }

    fn rearm_wake_sleep(&mut self) {
        let remaining = self.deadline.duration_since((self.time_getter)());
        let wake_deadline = timeout_now().saturating_add_nanos(remaining);
        self.sleep.reset(wake_deadline);
    }

    #[cfg(test)]
    #[must_use]
    const fn deadline(&self) -> Time {
        self.deadline
    }
}

impl<F> std::future::Future for ResolverTimeout<F>
where
    F: std::future::Future + Unpin,
{
    type Output = Result<F::Output, Elapsed>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(Elapsed::new(this.deadline)));
        }

        if let Poll::Ready(output) = Pin::new(&mut this.future).poll(cx) {
            this.completed = true;
            return Poll::Ready(Ok(output));
        }

        if (this.time_getter)() >= this.deadline {
            this.completed = true;
            return Poll::Ready(Err(Elapsed::new(this.deadline)));
        }

        match Pin::new(&mut this.sleep).poll(cx) {
            Poll::Ready(()) => {
                if (this.time_getter)() >= this.deadline {
                    this.completed = true;
                    return Poll::Ready(Err(Elapsed::new(this.deadline)));
                }

                // The wake source fired before the injected clock reached the
                // authoritative deadline, so re-arm for the remaining duration.
                this.rearm_wake_sleep();
                let _ = Pin::new(&mut this.sleep).poll(cx);
            }
            Poll::Pending => {}
        }

        Poll::Pending
    }
}

async fn spawn_blocking_dns<F, T>(f: F) -> Result<T, DnsError>
where
    F: FnOnce() -> Result<T, DnsError> + Send + 'static,
    T: Send + 'static,
{
    // Keep resolver behavior independent from any ambient current `Cx`.
    // This phase-0 path always uses a dedicated thread for synchronous DNS/connect work.
    spawn_blocking_on_thread(f).await
}

fn validate_lookup_hostname(host: &str) -> Result<(), DnsError> {
    // Absolute hostnames may include a trailing root dot, which should not
    // count against the 253-byte hostname limit for validation.
    let validated_host = host.strip_suffix('.').unwrap_or(host);
    if validated_host.is_empty() || validated_host.len() > 253 {
        return Err(DnsError::InvalidHost(host.to_string()));
    }

    if validated_host
        .split('.')
        .any(|label| label.is_empty() || label.len() > 63)
    {
        return Err(DnsError::InvalidHost(host.to_string()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::Cx;
    use futures_lite::future;
    use std::future::{Future, pending};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Wake, Waker};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    thread_local! {
        static TEST_NOW: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    fn set_test_time(nanos: u64) {
        TEST_NOW.with(|now: &std::cell::Cell<u64>| now.set(nanos));
    }

    fn test_time() -> Time {
        Time::from_nanos(TEST_NOW.with(std::cell::Cell::get))
    }

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
        fn wake_by_ref(self: &Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Arc::new(NoopWaker).into()
    }

    struct CountingWaker(AtomicUsize);

    impl CountingWaker {
        fn new() -> Arc<Self> {
            Arc::new(Self(AtomicUsize::new(0)))
        }

        fn count(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn resolver_ip_passthrough() {
        init_test("resolver_ip_passthrough");

        // Create a simple blocking test for IP passthrough
        let result = Resolver::query_ip_sync("127.0.0.1");
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        let lookup = result.unwrap();
        let len = lookup.len();
        crate::assert_with_log!(len == 1, "len", 1, len);
        let first = lookup.first().unwrap();
        let expected = "127.0.0.1".parse::<IpAddr>().unwrap();
        crate::assert_with_log!(first == expected, "addr", expected, first);
        crate::test_complete!("resolver_ip_passthrough");
    }

    #[test]
    fn resolver_localhost() {
        init_test("resolver_localhost");

        // Localhost should resolve
        let result = Resolver::query_ip_sync("localhost");
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        let lookup = result.unwrap();
        let empty = lookup.is_empty();
        crate::assert_with_log!(!empty, "not empty", false, empty);
        crate::test_complete!("resolver_localhost");
    }

    #[test]
    fn resolver_invalid_host() {
        init_test("resolver_invalid_host");

        let resolver = Resolver::new();
        let result = future::block_on(async { resolver.lookup_ip("").await });
        let invalid_host = matches!(result, Err(DnsError::InvalidHost(host)) if host.is_empty());
        crate::assert_with_log!(invalid_host, "empty hostname rejected", true, invalid_host);

        crate::test_complete!("resolver_invalid_host");
    }

    #[test]
    fn resolver_invalid_hostname_fails_before_cache_lookup() {
        init_test("resolver_invalid_hostname_fails_before_cache_lookup");

        let resolver = Resolver::with_config(ResolverConfig {
            timeout: Duration::ZERO,
            ..Default::default()
        });
        resolver
            .cache
            .put_negative_ip_no_records("cached..invalid.example");

        let result =
            future::block_on(async { resolver.lookup_ip("cached..invalid.example").await });
        let invalid = matches!(
            result,
            Err(DnsError::InvalidHost(ref host)) if host == "cached..invalid.example"
        );
        crate::assert_with_log!(
            invalid,
            "invalid hostname must reject before consulting cache",
            true,
            format!("{result:?}")
        );

        crate::test_complete!("resolver_invalid_hostname_fails_before_cache_lookup");
    }

    #[test]
    fn resolver_rejects_hostname_with_empty_label() {
        init_test("resolver_rejects_hostname_with_empty_label");

        let resolver = Resolver::with_config(ResolverConfig {
            timeout: Duration::ZERO,
            cache_enabled: false,
            ..Default::default()
        });
        let result = future::block_on(async { resolver.lookup_ip("example..com").await });
        let invalid = matches!(
            result,
            Err(DnsError::InvalidHost(ref host)) if host == "example..com"
        );
        crate::assert_with_log!(
            invalid,
            "hostname with empty label rejected before resolver fallback",
            true,
            format!("{result:?}")
        );

        crate::test_complete!("resolver_rejects_hostname_with_empty_label");
    }

    #[test]
    fn resolver_rejects_hostname_with_overlong_label() {
        init_test("resolver_rejects_hostname_with_overlong_label");

        let overlong = format!("{}.example", "a".repeat(64));
        let resolver = Resolver::with_config(ResolverConfig {
            timeout: Duration::ZERO,
            cache_enabled: false,
            ..Default::default()
        });
        let result = future::block_on(async { resolver.lookup_ip(&overlong).await });
        let invalid = matches!(
            result,
            Err(DnsError::InvalidHost(ref host)) if host == &overlong
        );
        crate::assert_with_log!(
            invalid,
            "hostname with >63-byte label rejected before resolver fallback",
            true,
            format!("{result:?}")
        );

        crate::test_complete!("resolver_rejects_hostname_with_overlong_label");
    }

    #[test]
    fn resolver_allows_max_length_absolute_hostname() {
        init_test("resolver_allows_max_length_absolute_hostname");

        let absolute_host = format!(
            "{}.{}.{}.{}.",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        crate::assert_with_log!(
            absolute_host.len() == 254,
            "absolute host length",
            254,
            absolute_host.len()
        );
        crate::assert_with_log!(
            absolute_host
                .strip_suffix('.')
                .is_some_and(|host| host.len() == 253),
            "validated host length",
            253,
            absolute_host.strip_suffix('.').map(str::len)
        );

        let resolver = Resolver::with_config(ResolverConfig {
            timeout: Duration::ZERO,
            cache_enabled: false,
            ..Default::default()
        });
        let result = future::block_on(async { resolver.lookup_ip(&absolute_host).await });
        let timed_out = matches!(result, Err(DnsError::Timeout));
        crate::assert_with_log!(
            timed_out,
            "max-length absolute hostname should pass validation and reach timeout gate",
            true,
            format!("{result:?}")
        );

        crate::test_complete!("resolver_allows_max_length_absolute_hostname");
    }

    #[test]
    fn resolver_rejects_absolute_hostname_that_exceeds_max_length() {
        init_test("resolver_rejects_absolute_hostname_that_exceeds_max_length");

        let absolute_host = format!(
            "{}.{}.{}.{}.",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );
        crate::assert_with_log!(
            absolute_host.len() == 255,
            "absolute host length",
            255,
            absolute_host.len()
        );
        crate::assert_with_log!(
            absolute_host
                .strip_suffix('.')
                .is_some_and(|host| host.len() == 254),
            "validated host length",
            254,
            absolute_host.strip_suffix('.').map(str::len)
        );

        let resolver = Resolver::with_config(ResolverConfig {
            timeout: Duration::ZERO,
            cache_enabled: false,
            ..Default::default()
        });
        let result = future::block_on(async { resolver.lookup_ip(&absolute_host).await });
        let invalid =
            matches!(result, Err(DnsError::InvalidHost(ref host)) if host == &absolute_host);
        crate::assert_with_log!(
            invalid,
            "overlong absolute hostname rejected",
            true,
            format!("{result:?}")
        );

        crate::test_complete!("resolver_rejects_absolute_hostname_that_exceeds_max_length");
    }

    #[test]
    fn resolver_cache_shared() {
        init_test("resolver_cache_shared");
        let resolver1 = Resolver::new();
        let resolver2 = resolver1.clone();

        resolver1.cache.put_ip(
            "test.example",
            &LookupIp::new(vec!["192.0.2.1".parse().unwrap()], Duration::from_mins(5)),
        );

        // Should be visible on resolver2 (shared cache)
        let stats = resolver2.cache_stats();
        crate::assert_with_log!(stats.size > 0, "cache size", ">0", stats.size);
        crate::test_complete!("resolver_cache_shared");
    }

    #[test]
    fn resolver_does_not_alias_trailing_dot_cache_entries() {
        init_test("resolver_does_not_alias_trailing_dot_cache_entries");
        let resolver = Resolver::with_config(ResolverConfig {
            timeout: Duration::ZERO,
            ..ResolverConfig::default()
        });

        resolver.cache.put_ip(
            "search-sensitive.example",
            &LookupIp::new(vec!["192.0.2.44".parse().unwrap()], Duration::from_mins(5)),
        );

        let result =
            future::block_on(async { resolver.lookup_ip("search-sensitive.example.").await });
        crate::assert_with_log!(
            matches!(result, Err(DnsError::Timeout)),
            "absolute hostname should not reuse non-dotted cache entry",
            true,
            format!("{result:?}")
        );

        crate::test_complete!("resolver_does_not_alias_trailing_dot_cache_entries");
    }

    #[test]
    fn resolver_does_not_alias_trailing_dot_negative_cache_entries() {
        init_test("resolver_does_not_alias_trailing_dot_negative_cache_entries");
        let resolver = Resolver::with_config(ResolverConfig {
            timeout: Duration::ZERO,
            ..ResolverConfig::default()
        });

        resolver
            .cache
            .put_negative_ip_no_records("search-sensitive.example");

        let result =
            future::block_on(async { resolver.lookup_ip("search-sensitive.example.").await });
        crate::assert_with_log!(
            matches!(result, Err(DnsError::Timeout)),
            "absolute hostname should not reuse non-dotted negative cache entry",
            true,
            format!("{result:?}")
        );

        crate::test_complete!("resolver_does_not_alias_trailing_dot_negative_cache_entries");
    }

    #[test]
    fn resolver_config_presets() {
        init_test("resolver_config_presets");
        let google = ResolverConfig::google();
        let empty = google.nameservers.is_empty();
        crate::assert_with_log!(!empty, "google nameservers", false, empty);

        let cloudflare = ResolverConfig::cloudflare();
        let empty = cloudflare.nameservers.is_empty();
        crate::assert_with_log!(!empty, "cloudflare nameservers", false, empty);
        crate::test_complete!("resolver_config_presets");
    }

    #[test]
    fn resolver_custom_nameservers_fail_closed() {
        init_test("resolver_custom_nameservers_fail_closed");

        let resolver = Resolver::with_config(ResolverConfig::google());
        let result = future::block_on(async { resolver.lookup_ip("localhost").await });
        let not_implemented = matches!(
            result,
            Err(DnsError::NotImplemented(
                "custom nameservers in Phase 0 resolver"
            ))
        );
        crate::assert_with_log!(
            not_implemented,
            "custom nameserver path rejected until explicit resolver transport exists",
            true,
            not_implemented
        );

        crate::test_complete!("resolver_custom_nameservers_fail_closed");
    }

    #[test]
    fn resolver_custom_nameservers_still_allow_ip_passthrough() {
        init_test("resolver_custom_nameservers_still_allow_ip_passthrough");

        let resolver = Resolver::with_config(ResolverConfig::google());
        let result = future::block_on(async { resolver.lookup_ip("127.0.0.1").await });
        crate::assert_with_log!(
            result.is_ok(),
            "literal IP passthrough",
            true,
            result.is_ok()
        );

        let lookup = result.unwrap();
        let len = lookup.len();
        crate::assert_with_log!(len == 1, "len", 1, len);
        let first = lookup.first().unwrap();
        let expected = "127.0.0.1".parse::<IpAddr>().unwrap();
        crate::assert_with_log!(first == expected, "addr", expected, first);

        crate::test_complete!("resolver_custom_nameservers_still_allow_ip_passthrough");
    }

    #[test]
    fn resolver_timeout_zero() {
        init_test("resolver_timeout_zero");

        let config = ResolverConfig {
            timeout: Duration::ZERO,
            cache_enabled: false,
            ..Default::default()
        };
        let resolver = Resolver::with_config(config);

        let result = future::block_on(async { resolver.lookup_ip("example.invalid").await });
        let timed_out = matches!(result, Err(DnsError::Timeout));
        crate::assert_with_log!(timed_out, "timed out", true, timed_out);

        crate::test_complete!("resolver_timeout_zero");
    }

    #[test]
    fn resolver_happy_eyeballs_single_address_zero_timeout_preserves_timeout_classification() {
        init_test(
            "resolver_happy_eyeballs_single_address_zero_timeout_preserves_timeout_classification",
        );

        let config = ResolverConfig {
            timeout: Duration::ZERO,
            cache_enabled: false,
            happy_eyeballs: true,
            ..Default::default()
        };
        let resolver = Resolver::with_config(config);

        let result =
            future::block_on(async { resolver.happy_eyeballs_connect("127.0.0.1", 80).await });
        let timed_out = matches!(result, Err(DnsError::Timeout));
        crate::assert_with_log!(
            timed_out,
            "happy eyeballs single-address path preserves timeout classification",
            true,
            timed_out
        );

        crate::test_complete!(
            "resolver_happy_eyeballs_single_address_zero_timeout_preserves_timeout_classification"
        );
    }

    #[test]
    fn resolver_happy_eyeballs_race_timeout_preserves_timeout_classification() {
        init_test("resolver_happy_eyeballs_race_timeout_preserves_timeout_classification");
        set_test_time(0);

        let resolver = Resolver::with_time_getter(
            ResolverConfig {
                timeout: Duration::from_secs(5),
                happy_eyeballs: true,
                ..Default::default()
            },
            test_time,
        );
        resolver.cache.put_ip(
            "dual.test",
            &LookupIp::new(
                vec![
                    "2001:db8::1".parse().unwrap(),
                    "198.51.100.1".parse().unwrap(),
                ],
                Duration::from_mins(5),
            ),
        );

        let mut future = Box::pin(resolver.happy_eyeballs_connect("dual.test", 80));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Future::poll(future.as_mut(), &mut cx);
        crate::assert_with_log!(
            first.is_pending(),
            "first poll pending",
            true,
            first.is_pending()
        );

        set_test_time(15_000_000_000);
        let second = Future::poll(future.as_mut(), &mut cx);
        let timed_out = matches!(second, Poll::Ready(Err(DnsError::Timeout)));
        crate::assert_with_log!(
            timed_out,
            "race timeout preserves timeout classification",
            true,
            timed_out
        );

        crate::test_complete!(
            "resolver_happy_eyeballs_race_timeout_preserves_timeout_classification"
        );
    }

    #[test]
    fn resolver_with_time_getter_threads_clock_into_cache() {
        init_test("resolver_with_time_getter_threads_clock_into_cache");
        set_test_time(0);

        let resolver = Resolver::with_time_getter(ResolverConfig::default(), test_time);

        crate::assert_with_log!(
            (resolver.time_getter())().as_nanos() == 0,
            "resolver time getter",
            0,
            (resolver.time_getter())().as_nanos()
        );
        crate::assert_with_log!(
            (resolver.cache.time_getter())().as_nanos() == 0,
            "cache time getter",
            0,
            (resolver.cache.time_getter())().as_nanos()
        );

        crate::test_complete!("resolver_with_time_getter_threads_clock_into_cache");
    }

    #[test]
    fn resolver_timeout_future_uses_time_getter_for_deadline() {
        init_test("resolver_timeout_future_uses_time_getter_for_deadline");
        set_test_time(1_000);

        let resolver = Resolver::with_time_getter(ResolverConfig::default(), test_time);
        let future = resolver.timeout_future(Duration::from_nanos(500), pending::<()>());

        crate::assert_with_log!(
            future.deadline() == Time::from_nanos(1_500),
            "deadline",
            Time::from_nanos(1_500),
            future.deadline()
        );

        crate::test_complete!("resolver_timeout_future_uses_time_getter_for_deadline");
    }

    #[test]
    fn resolver_timeout_future_poll_honors_custom_time_getter() {
        init_test("resolver_timeout_future_poll_honors_custom_time_getter");
        set_test_time(1_000);

        let resolver = Resolver::with_time_getter(ResolverConfig::default(), test_time);
        let mut future = resolver.timeout_future(Duration::from_nanos(500), pending::<()>());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first: Poll<Result<(), Elapsed>> = Future::poll(Pin::new(&mut future), &mut cx);
        crate::assert_with_log!(
            first.is_pending(),
            "first poll pending",
            true,
            first.is_pending()
        );

        set_test_time(2_000);
        let second: Poll<Result<(), Elapsed>> = Future::poll(Pin::new(&mut future), &mut cx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Err(_))),
            "second poll elapsed",
            true,
            matches!(second, Poll::Ready(Err(_)))
        );

        crate::test_complete!("resolver_timeout_future_poll_honors_custom_time_getter");
    }

    #[test]
    fn resolver_timeout_future_rearms_wake_source_when_timer_epoch_differs() {
        init_test("resolver_timeout_future_rearms_wake_source_when_timer_epoch_differs");
        set_test_time(0);

        let clock = Arc::new(crate::time::VirtualClock::starting_at(Time::from_secs(5)));
        let timer = crate::time::TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            crate::types::RegionId::new_for_test(1, 0),
            crate::types::TaskId::new_for_test(1, 0),
            crate::types::Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let resolver = Resolver::with_time_getter(ResolverConfig::default(), test_time);
        let mut future = resolver.timeout_future(Duration::from_nanos(500), pending::<()>());
        let waker = CountingWaker::new();
        let waker_handle = waker.clone();
        let task_waker: Waker = waker.into();
        let mut cx = Context::from_waker(&task_waker);

        let first: Poll<Result<(), Elapsed>> = Future::poll(Pin::new(&mut future), &mut cx);
        crate::assert_with_log!(
            first.is_pending(),
            "first poll pending",
            true,
            first.is_pending()
        );
        crate::assert_with_log!(
            timer.pending_count() == 1,
            "wake source registered against ambient timer",
            1,
            timer.pending_count()
        );

        clock.advance(500);
        let fired = timer.process_timers();
        crate::assert_with_log!(fired == 1, "timer fired once", 1, fired);
        crate::assert_with_log!(
            waker_handle.count() > 0,
            "timer wake reached task",
            ">0",
            waker_handle.count()
        );

        let second: Poll<Result<(), Elapsed>> = Future::poll(Pin::new(&mut future), &mut cx);
        crate::assert_with_log!(
            second.is_pending(),
            "ambient wake alone must not expire custom-clock timeout",
            true,
            second.is_pending()
        );
        crate::assert_with_log!(
            timer.pending_count() == 1,
            "wake source re-armed after early ambient wake",
            1,
            timer.pending_count()
        );

        set_test_time(500);
        let third: Poll<Result<(), Elapsed>> = Future::poll(Pin::new(&mut future), &mut cx);
        let elapsed_deadline = match third {
            Poll::Ready(Err(elapsed)) => Some(elapsed.deadline()),
            _ => None,
        };
        crate::assert_with_log!(
            elapsed_deadline == Some(Time::from_nanos(500)),
            "timeout should follow injected clock deadline",
            Some(Time::from_nanos(500)),
            elapsed_deadline
        );

        crate::test_complete!(
            "resolver_timeout_future_rearms_wake_source_when_timer_epoch_differs"
        );
    }

    #[test]
    fn resolver_default_timeout_deadline_ignores_current_cx_timer_driver() {
        init_test("resolver_default_timeout_deadline_ignores_current_cx_timer_driver");

        let clock = Arc::new(crate::time::VirtualClock::new());
        clock.set(Time::from_nanos(5_000_000_000));

        let cx = Cx::new_with_drivers(
            crate::types::RegionId::new_for_test(0, 0),
            crate::types::TaskId::new_for_test(0, 0),
            crate::types::Budget::INFINITE,
            None,
            None,
            None,
            Some(crate::time::TimerDriverHandle::with_virtual_clock(clock)),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let before = crate::time::wall_now();
        let resolver = Resolver::new();
        let future = resolver.timeout_future(Duration::from_nanos(500), pending::<()>());
        let after = crate::time::wall_now();
        let deadline = future.deadline();
        let min_deadline = before.saturating_add_nanos(500);
        let max_deadline = after.saturating_add_nanos(500);

        crate::assert_with_log!(
            deadline.as_nanos() >= min_deadline.as_nanos()
                && deadline.as_nanos() <= max_deadline.as_nanos(),
            "default deadline should follow wall clock, not ambient timer driver",
            (min_deadline, max_deadline),
            deadline
        );

        crate::test_complete!("resolver_default_timeout_deadline_ignores_current_cx_timer_driver");
    }

    #[test]
    fn resolver_blocking_dns_uses_fallback_thread_without_pool() {
        init_test("resolver_blocking_dns_uses_fallback_thread_without_pool");
        let cx: Cx = Cx::for_testing();
        let _guard = Cx::set_current(Some(cx));
        let current_id = std::thread::current().id();

        let thread_id = future::block_on(async {
            spawn_blocking_dns(|| Ok::<_, DnsError>(std::thread::current().id()))
                .await
                .unwrap()
        });

        crate::assert_with_log!(
            thread_id != current_id,
            "uses fallback thread",
            false,
            thread_id == current_id
        );

        crate::test_complete!("resolver_blocking_dns_uses_fallback_thread_without_pool");
    }

    #[test]
    fn resolver_blocking_dns_ignores_current_pool_and_uses_dedicated_thread() {
        init_test("resolver_blocking_dns_ignores_current_pool_and_uses_dedicated_thread");

        let pool = crate::runtime::BlockingPool::new(1, 1);
        let cx: Cx = Cx::for_testing().with_blocking_pool_handle(Some(pool.handle()));
        let _guard = Cx::set_current(Some(cx));

        let thread_name = future::block_on(async {
            spawn_blocking_dns(|| {
                Ok::<_, DnsError>(
                    std::thread::current()
                        .name()
                        .unwrap_or("unnamed")
                        .to_string(),
                )
            })
            .await
            .unwrap()
        });

        crate::assert_with_log!(
            thread_name == "asupersync-blocking",
            "resolver DNS fallback should stay on dedicated thread even with ambient pool",
            "asupersync-blocking",
            thread_name
        );

        crate::test_complete!(
            "resolver_blocking_dns_ignores_current_pool_and_uses_dedicated_thread"
        );
    }

    #[test]
    fn error_display_formats() {
        init_test("error_display_formats");

        // Test error display messages for failure mapping
        let no_records = DnsError::NoRecords("test.example".to_string());
        let msg = format!("{no_records}");
        crate::assert_with_log!(
            msg.contains("no DNS records"),
            "no records msg",
            true,
            msg.contains("no DNS records")
        );

        let timeout = DnsError::Timeout;
        let msg = format!("{timeout}");
        crate::assert_with_log!(
            msg.contains("timed out"),
            "timeout msg",
            true,
            msg.contains("timed out")
        );

        let io_err = DnsError::Io("connection refused".to_string());
        let msg = format!("{io_err}");
        crate::assert_with_log!(
            msg.contains("I/O error"),
            "io error msg",
            true,
            msg.contains("I/O error")
        );

        let invalid = DnsError::InvalidHost(String::new());
        let msg = format!("{invalid}");
        crate::assert_with_log!(
            msg.contains("invalid hostname"),
            "invalid msg",
            true,
            msg.contains("invalid hostname")
        );

        let not_impl = DnsError::NotImplemented("SRV");
        let msg = format!("{not_impl}");
        crate::assert_with_log!(
            msg.contains("not implemented"),
            "not impl msg",
            true,
            msg.contains("not implemented")
        );

        crate::test_complete!("error_display_formats");
    }

    #[test]
    fn error_from_io() {
        init_test("error_from_io");

        // Test io::Error conversion
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let dns_err: DnsError = io_err.into();
        let is_io = matches!(dns_err, DnsError::Io(_));
        crate::assert_with_log!(is_io, "is io error", true, is_io);

        crate::test_complete!("error_from_io");
    }

    #[test]
    fn resolver_nonexistent_domain() {
        init_test("resolver_nonexistent_domain");

        // Try to resolve a domain that definitely doesn't exist
        let result = Resolver::query_ip_sync("this-domain-definitely-does-not-exist.invalid");
        // Should fail with either NoRecords or Io error depending on DNS resolver behavior
        crate::assert_with_log!(result.is_err(), "nonexistent fails", true, result.is_err());

        crate::test_complete!("resolver_nonexistent_domain");
    }

    #[test]
    fn resolver_classifies_no_such_host_io_as_no_records() {
        init_test("resolver_classifies_no_such_host_io_as_no_records");

        let err = io::Error::new(io::ErrorKind::NotFound, "No such host is known");
        let classified = Resolver::classify_lookup_io_error("missing.example", &err);
        crate::assert_with_log!(
            matches!(classified, DnsError::NoRecords(ref host) if host == "missing.example"),
            "NXDOMAIN-like io error maps to NoRecords",
            true,
            format!("{classified:?}")
        );

        crate::test_complete!("resolver_classifies_no_such_host_io_as_no_records");
    }

    #[test]
    fn resolver_lookup_ip_serves_cached_negative_no_records_until_negative_ttl_expires() {
        init_test(
            "resolver_lookup_ip_serves_cached_negative_no_records_until_negative_ttl_expires",
        );
        set_test_time(0);
        let config = ResolverConfig {
            cache_config: CacheConfig {
                negative_ttl: Duration::from_millis(10),
                ..CacheConfig::default()
            },
            ..ResolverConfig::default()
        };
        let resolver = Resolver::with_time_getter(config, test_time);
        resolver.cache.put_negative_ip_no_records("localhost");

        let cached = future::block_on(async { resolver.lookup_ip("localhost").await });
        crate::assert_with_log!(
            matches!(cached, Err(DnsError::NoRecords(ref host)) if host == "localhost"),
            "cached negative lookup returned",
            true,
            format!("{cached:?}")
        );

        set_test_time(
            Duration::from_millis(11)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        let refreshed = future::block_on(async { resolver.lookup_ip("localhost").await });
        crate::assert_with_log!(
            refreshed.is_ok(),
            "expired negative entry falls through to fresh resolution",
            true,
            refreshed.is_ok()
        );
        let refreshed = refreshed.expect("localhost should resolve after negative TTL expiry");
        crate::assert_with_log!(
            !refreshed.is_empty(),
            "fresh localhost resolution yields addresses",
            true,
            !refreshed.is_empty()
        );

        crate::test_complete!(
            "resolver_lookup_ip_serves_cached_negative_no_records_until_negative_ttl_expires"
        );
    }
}
