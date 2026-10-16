//! Async DNS resolver with caching and Happy Eyeballs support.
//!
//! # Cancel Safety
//!
//! - `lookup_ip`: Cancel-safe; a cancelled task gets `DnsError::Cancelled` at once.
//! - `happy_eyeballs_connect`: Cancel-safe, connection attempts are cancelled on drop.
//!
//! # Implementation Notes
//!
//! `lookup_ip` keeps the system-resolver fast path for the default configuration
//! so search-domain semantics remain faithful to the host environment. When
//! explicit nameservers are configured, or when record-specific lookups (MX,
//! SRV, TXT) are requested, the resolver uses its own DNS transport over
//! UDP/TCP on the blocking pool.

use std::future::Future;
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream as StdTcpStream, ToSocketAddrs,
    UdpSocket as StdUdpSocket,
};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use std::time::Instant;

use super::cache::{CacheConfig, CacheStats, DnsCache};
use super::error::DnsError;
use super::lookup::{HappyEyeballs, LookupIp, LookupMx, LookupSrv, LookupTxt};
use crate::net::TcpStream;
use crate::runtime::spawn_blocking::spawn_blocking_on_thread;
use crate::time::{Elapsed, Sleep};
use crate::types::Time;
use crate::util::{EntropySource, OsEntropy};

/// DNS resolver configuration.
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    /// Nameservers to use (empty = use system resolvers).
    ///
    /// When empty, `lookup_ip` uses the system resolver while record-specific
    /// lookups discover system nameservers where available. When non-empty, all
    /// network DNS queries are sent directly to this server set.
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
    entropy: Arc<dyn EntropySource>,
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
            entropy: Arc::new(OsEntropy),
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
            entropy: Arc::new(OsEntropy),
        }
    }

    /// Overrides the entropy source.
    #[must_use]
    pub fn with_entropy(mut self, entropy: Arc<dyn EntropySource>) -> Self {
        self.entropy = entropy;
        self
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
        // Literal IPs (IPv6 also in URL brackets) need no resolver selection.
        if let Some(ip) = parse_ip_literal(host) {
            return Ok(LookupIp::new(vec![ip], Duration::from_secs(0)));
        }

        validate_lookup_hostname(host)?;

        if is_invalid_special_use_domain(host) {
            return Err(DnsError::NoRecords(host.to_string()));
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

        let result = if self.config.nameservers.is_empty() {
            self.do_lookup_ip(host).await
        } else {
            self.do_lookup_ip_with_nameservers(host).await
        };

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
    /// This function is cancel-safe. If the future is dropped or times out, the
    /// system lookup in progress finishes on its thread; no further retry starts.
    async fn do_lookup_ip(&self, host: &str) -> Result<LookupIp, DnsError> {
        validate_lookup_hostname(host)?;

        let retries = self.config.retries;
        if self.config.timeout.is_zero() {
            return Err(DnsError::Timeout);
        }
        let host = host.to_string();

        // Each blocking attempt can take seconds in a DNS outage: none starts
        // after the caller gave up (timeout, drop or cancellation).
        let abandoned = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = Arc::clone(&abandoned);
        let deadline = Instant::now().checked_add(self.config.timeout);

        // Keep DNS resolution off the runtime thread even when a current `Cx`
        // exists without a blocking pool handle.
        let lookup = Box::pin(spawn_blocking_dns(move || {
            retry_system_lookup(
                retries,
                || {
                    stop.load(std::sync::atomic::Ordering::Relaxed)
                        || deadline.is_some_and(|deadline| Instant::now() >= deadline)
                },
                || Self::query_ip_sync(&host),
            )
        }));
        let _abandon = AbandonOnDrop(abandoned);

        self.timeout_future(self.config.timeout, lookup)
            .await
            .unwrap_or(Err(DnsError::Timeout))
    }

    async fn do_lookup_ip_with_nameservers(&self, host: &str) -> Result<LookupIp, DnsError> {
        validate_lookup_hostname(host)?;

        let retries = self.config.retries;
        let timeout = self.config.timeout;
        if timeout.is_zero() {
            return Err(DnsError::Timeout);
        }
        let host = host.to_string();
        let nameservers = self.effective_nameservers()?;
        let entropy = Arc::clone(&self.entropy);

        let lookup = Box::pin(spawn_blocking_dns(move || {
            Self::query_ip_with_nameservers_sync(
                &host,
                &nameservers,
                retries,
                query_budget(timeout),
                entropy.as_ref(),
            )
        }));

        self.timeout_future(timeout, lookup)
            .await
            .unwrap_or(Err(DnsError::Timeout))
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

        let socket_addrs: Vec<SocketAddr> =
            addrs.iter().map(|ip| SocketAddr::new(*ip, port)).collect();

        // If Happy Eyeballs is disabled, just try sequentially
        if !self.config.happy_eyeballs {
            let mut sorted_addrs = socket_addrs;
            sorted_addrs.sort_by_key(|a| i32::from(!a.is_ipv6()));
            return self.connect_sequential(&sorted_addrs).await;
        }

        // Happy Eyeballs: race connections with staggered starts
        self.connect_happy_eyeballs(&socket_addrs).await
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
    /// This function is cancel-safe. It uses the runtime's timeout-aware TCP
    /// connect path so timed-out attempts do not pin a fallback blocking thread
    /// until the operating system eventually gives up on the socket.
    async fn try_connect_timeout(
        &self,
        addr: SocketAddr,
        timeout_duration: Duration,
    ) -> Result<TcpStream, DnsError> {
        self.try_connect_timeout_with_connector(
            addr,
            timeout_duration,
            TcpStream::connect_timeout_with_time_getter,
        )
        .await
    }

    async fn try_connect_timeout_with_connector<Fut, Connector>(
        &self,
        addr: SocketAddr,
        timeout_duration: Duration,
        connector: Connector,
    ) -> Result<TcpStream, DnsError>
    where
        Fut: Future<Output = io::Result<TcpStream>>,
        Connector: FnOnce(SocketAddr, Duration, fn() -> Time) -> Fut,
    {
        if timeout_duration.is_zero() {
            return Err(DnsError::Timeout);
        }

        connector(addr, timeout_duration, self.time_getter)
            .await
            .map_err(|err| Self::classify_connect_error(&err))
    }

    /// Looks up MX records for a domain.
    pub async fn lookup_mx(&self, domain: &str) -> Result<LookupMx, DnsError> {
        validate_dns_record_name(domain)?;
        let domain = domain.to_string();
        let nameservers = self.effective_nameservers()?;
        let retries = self.config.retries;
        let timeout = self.config.timeout;
        let entropy = Arc::clone(&self.entropy);
        if timeout.is_zero() {
            return Err(DnsError::Timeout);
        }

        let lookup = Box::pin(spawn_blocking_dns(move || {
            let answers = Self::query_records_sync(
                &domain,
                DnsQueryType::Mx,
                &nameservers,
                retries,
                timeout,
                entropy.as_ref(),
            )?;
            let mut records = Vec::new();
            for answer in answers {
                if let DnsRecordData::Mx {
                    preference,
                    exchange,
                } = answer.data
                {
                    records.push(crate::net::dns::MxRecord {
                        preference,
                        exchange,
                    });
                }
            }
            if records.is_empty() {
                return Err(DnsError::NoRecords(domain));
            }
            Ok(LookupMx::new(records))
        }));

        self.timeout_future(timeout, lookup)
            .await
            .unwrap_or(Err(DnsError::Timeout))
    }

    /// Looks up SRV records.
    pub async fn lookup_srv(&self, name: &str) -> Result<LookupSrv, DnsError> {
        validate_dns_record_name(name)?;
        let name = name.to_string();
        let nameservers = self.effective_nameservers()?;
        let retries = self.config.retries;
        let timeout = self.config.timeout;
        let entropy = Arc::clone(&self.entropy);
        if timeout.is_zero() {
            return Err(DnsError::Timeout);
        }

        let lookup = Box::pin(spawn_blocking_dns(move || {
            let answers = Self::query_records_sync(
                &name,
                DnsQueryType::Srv,
                &nameservers,
                retries,
                timeout,
                entropy.as_ref(),
            )?;
            let mut records = Vec::new();
            for answer in answers {
                if let DnsRecordData::Srv {
                    priority,
                    weight,
                    port,
                    target,
                } = answer.data
                {
                    records.push(crate::net::dns::SrvRecord {
                        priority,
                        weight,
                        port,
                        target,
                    });
                }
            }
            if records.is_empty() {
                return Err(DnsError::NoRecords(name));
            }
            Ok(LookupSrv::new(records))
        }));

        self.timeout_future(timeout, lookup)
            .await
            .unwrap_or(Err(DnsError::Timeout))
    }

    /// Looks up TXT records.
    pub async fn lookup_txt(&self, name: &str) -> Result<LookupTxt, DnsError> {
        validate_dns_record_name(name)?;
        let name = name.to_string();
        let nameservers = self.effective_nameservers()?;
        let retries = self.config.retries;
        let timeout = self.config.timeout;
        let entropy = Arc::clone(&self.entropy);
        if timeout.is_zero() {
            return Err(DnsError::Timeout);
        }

        let lookup = Box::pin(spawn_blocking_dns(move || {
            let answers = Self::query_records_sync(
                &name,
                DnsQueryType::Txt,
                &nameservers,
                retries,
                timeout,
                entropy.as_ref(),
            )?;
            let mut records = Vec::new();
            for answer in answers {
                if let DnsRecordData::Txt(text) = answer.data {
                    records.push(text);
                }
            }
            if records.is_empty() {
                return Err(DnsError::NoRecords(name));
            }
            Ok(LookupTxt::new(records))
        }));

        self.timeout_future(timeout, lookup)
            .await
            .unwrap_or(Err(DnsError::Timeout))
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

    fn effective_nameservers(&self) -> Result<Vec<SocketAddr>, DnsError> {
        if !self.config.nameservers.is_empty() {
            return validate_configured_nameservers(&self.config.nameservers);
        }
        Ok(system_nameservers())
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
            entropy: Arc::clone(&self.entropy),
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
    /// The re-armed wake sleep completed while registering and must be reset
    /// before it is polled again (asupersync-bi2462.168).
    sleep_done: bool,
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
            sleep_done: false,
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

        if this.sleep_done {
            this.rearm_wake_sleep();
            this.sleep_done = false;
        }

        // A deadline wrapper polls its wake sleep with `poll_deadline`: owner
        // cancellation is not elapsed time, and the lookup keeps its real
        // deadline (the convention of bi2462.110's timeout fix).
        match Pin::new(&mut this.sleep).poll_deadline(cx) {
            Poll::Ready(()) => {
                if (this.time_getter)() >= this.deadline {
                    this.completed = true;
                    return Poll::Ready(Err(Elapsed::new(this.deadline)));
                }

                // The wake source fired before the injected clock reached the
                // authoritative deadline, so re-arm for the remaining duration.
                // A completed Sleep is never polled again: if the re-armed one
                // is already due, reset it on the next poll.
                this.rearm_wake_sleep();
                if Pin::new(&mut this.sleep).poll_deadline(cx).is_ready() {
                    this.sleep_done = true;
                    cx.waker().wake_by_ref();
                }
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
    // Gated like net::lookup_all; then a dedicated thread a cancelled caller stops waiting for.
    crate::cx::io_gate::require_ambient_io("net::dns::Resolver")?;
    unless_cancelled(crate::cx::Cx::current(), spawn_blocking_on_thread(f)).await
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
        .any(|label| !is_valid_lookup_hostname_label(label))
    {
        return Err(DnsError::InvalidHost(host.to_string()));
    }

    Ok(())
}

fn is_valid_lookup_hostname_label(label: &str) -> bool {
    if label.is_empty() || label.len() > 63 {
        return false;
    }

    let mut bytes = label.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !(first.is_ascii_alphanumeric() || first == b'_') {
        return false;
    }

    let mut last = first;
    for byte in bytes {
        if !(byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_') {
            return false;
        }
        last = byte;
    }

    last.is_ascii_alphanumeric()
}

fn is_invalid_special_use_domain(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    host.eq_ignore_ascii_case("invalid") || host.to_ascii_lowercase().ends_with(".invalid")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DnsQueryType {
    A,
    Aaaa,
    Mx,
    Txt,
    Srv,
    Cname,
}

impl DnsQueryType {
    const DNS_CLASS_IN: u16 = 1;

    const fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Cname => 5,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Aaaa => 28,
            Self::Srv => 33,
        }
    }

    fn from_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::A),
            5 => Some(Self::Cname),
            15 => Some(Self::Mx),
            16 => Some(Self::Txt),
            28 => Some(Self::Aaaa),
            33 => Some(Self::Srv),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
struct DnsAnswer {
    name: String,
    ttl: Duration,
    data: DnsRecordData,
}

#[derive(Clone, Debug)]
enum DnsRecordData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Mx {
        preference: u16,
        exchange: String,
    },
    Txt(String),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
}

#[derive(Debug)]
struct ParsedDnsResponse {
    truncated: bool,
    rcode: u8,
    answers: Vec<DnsAnswer>,
}

#[derive(Debug)]
enum QuerySelection {
    Records(Vec<DnsAnswer>),
    Alias(String),
    NoRecords,
}

const DNS_MAX_EXPANDED_NAME_LEN: usize = 253;

fn validate_dns_record_name(name: &str) -> Result<(), DnsError> {
    let validated_name = name.strip_suffix('.').unwrap_or(name);
    if validated_name.is_empty() || validated_name.len() > 253 {
        return Err(DnsError::InvalidHost(name.to_string()));
    }

    if validated_name
        .split('.')
        .any(|label| !is_valid_dns_record_label(label))
    {
        return Err(DnsError::InvalidHost(name.to_string()));
    }

    Ok(())
}

fn is_valid_dns_record_label(label: &str) -> bool {
    if label.is_empty() || label.len() > 63 {
        return false;
    }

    let bytes = label.as_bytes();
    let first = bytes[0];
    if !(first.is_ascii_alphanumeric() || first == b'_') {
        return false;
    }

    let last = *bytes.last().expect("checked non-empty label");
    if !last.is_ascii_alphanumeric() {
        return false;
    }

    bytes[1..bytes.len().saturating_sub(1)]
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_')
}

fn canonical_dns_name(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

fn validate_nameserver_addr(nameserver: SocketAddr) -> Result<SocketAddr, DnsError> {
    if nameserver.port() == 0 {
        return Err(DnsError::Io(format!(
            "invalid DNS nameserver {nameserver}: port must be non-zero"
        )));
    }
    if nameserver.ip().is_unspecified() {
        return Err(DnsError::Io(format!(
            "invalid DNS nameserver {nameserver}: unspecified address is not allowed"
        )));
    }
    Ok(nameserver)
}

fn validate_configured_nameservers(
    nameservers: &[SocketAddr],
) -> Result<Vec<SocketAddr>, DnsError> {
    let mut validated = Vec::with_capacity(nameservers.len());
    for nameserver in nameservers.iter().copied() {
        let nameserver = validate_nameserver_addr(nameserver)?;
        if !validated.contains(&nameserver) {
            validated.push(nameserver);
        }
    }
    Ok(validated)
}

fn system_nameservers() -> Vec<SocketAddr> {
    std::fs::read_to_string("/etc/resolv.conf")
        .map(|contents| parse_resolv_conf_nameservers(&contents))
        .unwrap_or_default()
}

fn parse_resolv_conf_nameservers(contents: &str) -> Vec<SocketAddr> {
    let mut nameservers = Vec::new();

    for line in contents.lines() {
        let line = line.split(['#', ';']).next().unwrap_or(line).trim();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.split_whitespace();
        let Some(keyword) = parts.next() else {
            continue;
        };
        if keyword != "nameserver" {
            continue;
        }

        let Some(value) = parts.next() else {
            continue;
        };

        if let Ok(ip) = value.parse::<IpAddr>() {
            let addr = SocketAddr::new(ip, 53);
            if validate_nameserver_addr(addr).is_ok() && !nameservers.contains(&addr) {
                nameservers.push(addr);
            }
        }
    }

    nameservers
}

#[cfg(any(test, feature = "test-internals"))]
/// Test-internals hook exposing the resolv.conf nameserver parser.
pub fn parse_resolv_conf_nameservers_for_test(contents: &str) -> Vec<SocketAddr> {
    parse_resolv_conf_nameservers(contents)
}

#[cfg(any(test, feature = "test-internals"))]
#[allow(dead_code)]
/// Test-internals hook exposing the binary DNS-response parser.
///
/// Returns only Ok/Err for the parse outcome (the parsed response itself is a
/// private type). Intended for fuzz targets that need the
/// no-panic + typed-error + no-infinite-loop oracle on attacker-controlled DNS
/// wire bytes (label compression pointer loops, oversized labels, truncated
/// headers, malformed RR).
pub fn parse_dns_response_for_fuzz(packet: &[u8], expected_id: u16) -> Result<(), DnsError> {
    parse_dns_response(packet, expected_id, None).map(|_| ())
}

#[cfg(any(test, feature = "test-internals"))]
#[allow(dead_code)]
/// Test-internals hook for the DNS name decoder (label-pointer bomb
/// surface). Same fuzz purpose as parse_dns_response_for_fuzz.
pub fn decode_dns_name_for_fuzz(packet: &[u8], offset: &mut usize) -> Result<String, DnsError> {
    decode_dns_name(packet, offset)
}

fn build_dns_query(name: &str, query_type: DnsQueryType, id: u16) -> Result<Vec<u8>, DnsError> {
    let mut query = Vec::with_capacity(512);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes()); // recursion desired
    query.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    query.extend_from_slice(&0u16.to_be_bytes()); // ancount
    query.extend_from_slice(&0u16.to_be_bytes()); // nscount
    query.extend_from_slice(&0u16.to_be_bytes()); // arcount
    encode_dns_name(name, &mut query)?;
    query.extend_from_slice(&query_type.code().to_be_bytes());
    query.extend_from_slice(&DnsQueryType::DNS_CLASS_IN.to_be_bytes());
    Ok(query)
}

fn encode_dns_name(name: &str, out: &mut Vec<u8>) -> Result<(), DnsError> {
    let canonical = name.strip_suffix('.').unwrap_or(name);
    if canonical.is_empty() || canonical.len() > 253 {
        return Err(DnsError::InvalidHost(name.to_string()));
    }
    for label in canonical.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DnsError::InvalidHost(name.to_string()));
        }
        let len = u8::try_from(label.len()).map_err(|_| DnsError::InvalidHost(name.to_string()))?;
        out.push(len);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

fn read_u16(packet: &[u8], offset: &mut usize) -> Result<u16, DnsError> {
    let bytes = packet
        .get(*offset..offset.saturating_add(2))
        .ok_or_else(|| DnsError::Protocol("truncated DNS packet".to_string()))?;
    *offset += 2;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(packet: &[u8], offset: &mut usize) -> Result<u32, DnsError> {
    let bytes = packet
        .get(*offset..offset.saturating_add(4))
        .ok_or_else(|| DnsError::Protocol("truncated DNS packet".to_string()))?;
    *offset += 4;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn push_decoded_dns_label(
    labels: &mut Vec<String>,
    expanded_len: &mut usize,
    label: &str,
) -> Result<(), DnsError> {
    let separator_len = usize::from(!labels.is_empty());
    let next_len = expanded_len
        .checked_add(separator_len)
        .and_then(|len| len.checked_add(label.len()))
        .ok_or_else(|| DnsError::Protocol("expanded DNS name exceeds 253 bytes".to_string()))?;
    if next_len > DNS_MAX_EXPANDED_NAME_LEN {
        return Err(DnsError::Protocol(
            "expanded DNS name exceeds 253 bytes".to_string(),
        ));
    }

    *expanded_len = next_len;
    labels.push(label.to_string());
    Ok(())
}

fn decode_dns_name(packet: &[u8], offset: &mut usize) -> Result<String, DnsError> {
    let (name, consumed) = decode_dns_name_inner(packet, *offset, 0)?;
    *offset = consumed;
    Ok(name)
}

fn decode_dns_name_inner(
    packet: &[u8],
    start: usize,
    depth: usize,
) -> Result<(String, usize), DnsError> {
    if depth > 16 {
        return Err(DnsError::Protocol(
            "DNS compression pointer loop".to_string(),
        ));
    }

    let mut labels = Vec::new();
    let mut expanded_len = 0usize;
    let mut offset = start;

    loop {
        let len = *packet
            .get(offset)
            .ok_or_else(|| DnsError::Protocol("truncated DNS name".to_string()))?;
        if len & 0xC0 == 0xC0 {
            let next = *packet
                .get(offset.saturating_add(1))
                .ok_or_else(|| DnsError::Protocol("truncated DNS name pointer".to_string()))?;
            let pointer = ((u16::from(len & 0x3F) << 8) | u16::from(next)) as usize;
            if pointer >= start {
                return Err(DnsError::Protocol(
                    "forward DNS compression pointer".to_string(),
                ));
            }
            let (suffix, _) = decode_dns_name_inner(packet, pointer, depth.saturating_add(1))?;
            if !suffix.is_empty() {
                push_decoded_dns_label(&mut labels, &mut expanded_len, &suffix)?;
            }
            return Ok((labels.join("."), offset.saturating_add(2)));
        }
        if len & 0xC0 != 0 {
            return Err(DnsError::Protocol("invalid DNS label encoding".to_string()));
        }

        offset += 1;
        if len == 0 {
            return Ok((labels.join("."), offset));
        }

        let end = offset.saturating_add(usize::from(len));
        let label_bytes = packet
            .get(offset..end)
            .ok_or_else(|| DnsError::Protocol("truncated DNS label".to_string()))?;
        let label = std::str::from_utf8(label_bytes)
            .map_err(|_| DnsError::Protocol("DNS label is not UTF-8".to_string()))?;
        push_decoded_dns_label(&mut labels, &mut expanded_len, label)?;
        offset = end;
    }
}

fn parse_dns_answer(packet: &[u8], offset: &mut usize) -> Result<Option<DnsAnswer>, DnsError> {
    let name = decode_dns_name(packet, offset)?;
    let rr_type = read_u16(packet, offset)?;
    let rr_class = read_u16(packet, offset)?;
    let ttl = read_u32(packet, offset)?;
    let rdlen = usize::from(read_u16(packet, offset)?);
    let rdata_offset = *offset;
    let rdata_end = rdata_offset.saturating_add(rdlen);
    if rdata_end > packet.len() {
        return Err(DnsError::Protocol("truncated DNS RDATA".to_string()));
    }
    if rr_class != DnsQueryType::DNS_CLASS_IN {
        *offset = rdata_end;
        return Ok(None);
    }

    let ensure_rdata_consumed = |cursor: usize, record_kind: &str| -> Result<(), DnsError> {
        match cursor.cmp(&rdata_end) {
            std::cmp::Ordering::Greater => Err(DnsError::Protocol(format!(
                "{record_kind} record name exceeds DNS RDATA length"
            ))),
            std::cmp::Ordering::Less => Err(DnsError::Protocol(format!(
                "{record_kind} record contains trailing bytes after DNS name"
            ))),
            std::cmp::Ordering::Equal => Ok(()),
        }
    };

    let data = match DnsQueryType::from_code(rr_type) {
        Some(DnsQueryType::A) if rdlen == 4 => {
            let bytes = &packet[rdata_offset..rdata_end];
            DnsRecordData::A(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
        }
        Some(DnsQueryType::Aaaa) if rdlen == 16 => {
            let bytes = &packet[rdata_offset..rdata_end];
            let segments = [
                u16::from_be_bytes([bytes[0], bytes[1]]),
                u16::from_be_bytes([bytes[2], bytes[3]]),
                u16::from_be_bytes([bytes[4], bytes[5]]),
                u16::from_be_bytes([bytes[6], bytes[7]]),
                u16::from_be_bytes([bytes[8], bytes[9]]),
                u16::from_be_bytes([bytes[10], bytes[11]]),
                u16::from_be_bytes([bytes[12], bytes[13]]),
                u16::from_be_bytes([bytes[14], bytes[15]]),
            ];
            DnsRecordData::Aaaa(Ipv6Addr::new(
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                segments[4],
                segments[5],
                segments[6],
                segments[7],
            ))
        }
        Some(DnsQueryType::Cname) => {
            let mut name_offset = rdata_offset;
            let alias = decode_dns_name(packet, &mut name_offset)?;
            ensure_rdata_consumed(name_offset, "CNAME")?;
            DnsRecordData::Cname(alias)
        }
        Some(DnsQueryType::Mx) => {
            let mut mx_offset = rdata_offset;
            let preference = read_u16(packet, &mut mx_offset)?;
            let exchange = decode_dns_name(packet, &mut mx_offset)?;
            ensure_rdata_consumed(mx_offset, "MX")?;
            DnsRecordData::Mx {
                preference,
                exchange,
            }
        }
        Some(DnsQueryType::Txt) => {
            let mut txt_offset = rdata_offset;
            let mut text = String::new();
            while txt_offset < rdata_end {
                let len = usize::from(packet[txt_offset]);
                txt_offset += 1;
                let end = txt_offset.saturating_add(len);
                // A TXT character-string must stay within this record's RDATA.
                // Bounding only by packet.len() would let an oversized length
                // prefix absorb bytes from the following record (cross-RDATA
                // over-read), the way CNAME/MX/SRV already reject via
                // ensure_rdata_consumed.
                if end > rdata_end {
                    return Err(DnsError::Protocol(
                        "TXT character-string exceeds DNS RDATA length".to_string(),
                    ));
                }
                let chunk = packet
                    .get(txt_offset..end)
                    .ok_or_else(|| DnsError::Protocol("truncated TXT record".to_string()))?;
                text.push_str(
                    std::str::from_utf8(chunk)
                        .map_err(|_| DnsError::Protocol("TXT record is not UTF-8".to_string()))?,
                );
                txt_offset = end;
            }
            DnsRecordData::Txt(text)
        }
        Some(DnsQueryType::Srv) => {
            let mut srv_offset = rdata_offset;
            let priority = read_u16(packet, &mut srv_offset)?;
            let weight = read_u16(packet, &mut srv_offset)?;
            let port = read_u16(packet, &mut srv_offset)?;
            let target = decode_dns_name(packet, &mut srv_offset)?;
            ensure_rdata_consumed(srv_offset, "SRV")?;
            DnsRecordData::Srv {
                priority,
                weight,
                port,
                target,
            }
        }
        _ => {
            *offset = rdata_end;
            return Ok(None);
        }
    };

    *offset = rdata_end;
    Ok(Some(DnsAnswer {
        name,
        ttl: Duration::from_secs(u64::from(ttl)),
        data,
    }))
}

/// Decodes the first question (name + qtype) from a DNS message, if present.
///
/// Used by the send paths to confirm a response echoes the question that was
/// sent — basic off-path spoof resistance on top of the transaction id and the
/// `connect()`ed socket (aasraf).
fn first_question(packet: &[u8]) -> Option<(String, u16)> {
    if packet.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut offset = 12;
    let name = decode_dns_name(packet, &mut offset).ok()?;
    let qtype = read_u16(packet, &mut offset).ok()?;
    Some((name, qtype))
}

fn parse_dns_response(
    packet: &[u8],
    expected_id: u16,
    expected_question: Option<&(String, u16)>,
) -> Result<ParsedDnsResponse, DnsError> {
    if packet.len() < 12 {
        return Err(DnsError::Protocol("DNS packet too short".to_string()));
    }

    let mut offset = 0;
    let id = read_u16(packet, &mut offset)?;
    if id != expected_id {
        return Err(DnsError::Protocol("mismatched DNS response id".to_string()));
    }

    let flags = read_u16(packet, &mut offset)?;
    if flags & 0x8000 == 0 {
        return Err(DnsError::Protocol(
            "received DNS query instead of response".to_string(),
        ));
    }
    let truncated = flags & 0x0200 != 0;
    let rcode = (flags & 0x000F) as u8;

    let question_count = usize::from(read_u16(packet, &mut offset)?);
    let answer_count = usize::from(read_u16(packet, &mut offset)?);
    let authority_count = usize::from(read_u16(packet, &mut offset)?);
    let additional_count = usize::from(read_u16(packet, &mut offset)?);

    let mut first_seen: Option<(String, u16)> = None;
    for index in 0..question_count {
        let qname = decode_dns_name(packet, &mut offset)?;
        let qtype = read_u16(packet, &mut offset)?;
        let _qclass = read_u16(packet, &mut offset)?;
        if index == 0 {
            first_seen = Some((qname, qtype));
        }
    }

    // Off-path spoof resistance: a genuine response echoes the question we
    // asked. Reject any response whose first question does not match the sent
    // query name (case-insensitively, per RFC 4343) and qtype (aasraf).
    if let Some((exp_name, exp_qtype)) = expected_question {
        let matches = matches!(
            &first_seen,
            Some((qname, qtype)) if qtype == exp_qtype && qname.eq_ignore_ascii_case(exp_name)
        );
        if !matches {
            return Err(DnsError::Protocol(
                "DNS response question does not match the query".to_string(),
            ));
        }
    }

    // RFC 1035 §4.1.1 / RFC 2181 §9: a truncated response (TC=1) must have its
    // content ignored and the query retried over a larger channel (TCP). Do NOT
    // parse the necessarily-incomplete answer section — a UDP datagram cut at
    // the 512-byte boundary leaves a partial trailing RR (or an `answer_count`
    // that exceeds the RRs actually present), so `parse_dns_answer` would run
    // off the end and return an error that escapes `send_udp_dns_query` and
    // aborts `query_nameserver` *before* its `if response.truncated` TCP
    // fallback — permanently losing records that TCP would have delivered. The
    // id and question were already validated above, so return the verified
    // header with no answers and let the caller escalate to TCP.
    if truncated {
        return Ok(ParsedDnsResponse {
            truncated,
            rcode,
            answers: Vec::new(),
        });
    }

    // Cap pre-allocation to prevent attacker-controlled answer_count
    // from causing excessive memory allocation (max 512 answers is
    // well beyond any legitimate DNS response).
    let mut answers = Vec::with_capacity(answer_count.min(512));
    for _ in 0..answer_count {
        if let Some(answer) = parse_dns_answer(packet, &mut offset)? {
            answers.push(answer);
        }
    }

    for _ in 0..authority_count.saturating_add(additional_count) {
        let _ = parse_dns_answer(packet, &mut offset)?;
    }

    Ok(ParsedDnsResponse {
        truncated,
        rcode,
        answers,
    })
}

fn dns_query_id(entropy: &dyn EntropySource) -> u16 {
    let mut bytes = [0u8; 2];
    entropy.fill_bytes(&mut bytes);
    let query_id = u16::from_be_bytes(bytes);
    if query_id == 0 { 0xA5A5 } else { query_id }
}

fn per_attempt_timeout(total_timeout: Duration, attempts: usize) -> Duration {
    if attempts <= 1 {
        return total_timeout;
    }

    let divided = total_timeout / u32::try_from(attempts).unwrap_or(u32::MAX);
    let floor = Duration::from_millis(50);
    if divided.is_zero() {
        total_timeout
    } else if divided < floor && total_timeout > floor {
        floor
    } else {
        divided
    }
}

fn dns_io_error(err: &io::Error) -> DnsError {
    match err.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => DnsError::Timeout,
        _ => DnsError::Io(err.to_string()),
    }
}

fn bind_addr_for(nameserver: SocketAddr) -> SocketAddr {
    if nameserver.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
    }
}

fn send_udp_dns_query(
    nameserver: SocketAddr,
    query: &[u8],
    expected_id: u16,
    timeout: Duration,
) -> Result<ParsedDnsResponse, DnsError> {
    let socket = StdUdpSocket::bind(bind_addr_for(nameserver)).map_err(|err| dns_io_error(&err))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|err| dns_io_error(&err))?;
    socket
        .set_write_timeout(Some(timeout))
        .map_err(|err| dns_io_error(&err))?;
    socket
        .connect(nameserver)
        .map_err(|err| dns_io_error(&err))?;
    socket.send(query).map_err(|err| dns_io_error(&err))?;

    let mut packet = [0u8; 2048];
    let len = socket.recv(&mut packet).map_err(|err| dns_io_error(&err))?;
    let expected_question = first_question(query);
    parse_dns_response(&packet[..len], expected_id, expected_question.as_ref())
}

fn send_tcp_dns_query(
    nameserver: SocketAddr,
    query: &[u8],
    expected_id: u16,
    timeout: Duration,
) -> Result<ParsedDnsResponse, DnsError> {
    let mut stream =
        StdTcpStream::connect_timeout(&nameserver, timeout).map_err(|err| dns_io_error(&err))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| dns_io_error(&err))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| dns_io_error(&err))?;

    let query_len = u16::try_from(query.len())
        .map_err(|_| DnsError::Protocol("DNS query too large for TCP transport".to_string()))?;
    stream
        .write_all(&query_len.to_be_bytes())
        .and_then(|()| stream.write_all(query))
        .map_err(|err| dns_io_error(&err))?;

    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .map_err(|err| dns_io_error(&err))?;
    let response_len = usize::from(u16::from_be_bytes(len_buf));
    let mut packet = vec![0u8; response_len];
    stream
        .read_exact(&mut packet)
        .map_err(|err| dns_io_error(&err))?;
    let _ = stream.shutdown(std::net::Shutdown::Both);
    let expected_question = first_question(query);
    parse_dns_response(&packet, expected_id, expected_question.as_ref())
}

fn query_nameserver(
    nameserver: SocketAddr,
    query: &[u8],
    expected_id: u16,
    timeout: Duration,
) -> Result<ParsedDnsResponse, DnsError> {
    let response = send_udp_dns_query(nameserver, query, expected_id, timeout)?;
    if response.truncated {
        send_tcp_dns_query(nameserver, query, expected_id, timeout)
    } else {
        Ok(response)
    }
}

fn select_records_for_query(
    query_name: &str,
    query_type: DnsQueryType,
    answers: &[DnsAnswer],
) -> QuerySelection {
    let wanted_name = canonical_dns_name(query_name);
    let mut matches = Vec::new();
    let mut alias = None;

    for answer in answers {
        if canonical_dns_name(&answer.name) != wanted_name {
            continue;
        }

        match (&answer.data, query_type) {
            (DnsRecordData::A(_), DnsQueryType::A)
            | (DnsRecordData::Aaaa(_), DnsQueryType::Aaaa)
            | (DnsRecordData::Mx { .. }, DnsQueryType::Mx)
            | (DnsRecordData::Txt(_), DnsQueryType::Txt)
            | (DnsRecordData::Srv { .. }, DnsQueryType::Srv) => matches.push(answer.clone()),
            (DnsRecordData::Cname(target), _) if alias.is_none() => alias = Some(target.clone()),
            _ => {}
        }
    }

    if !matches.is_empty() {
        QuerySelection::Records(matches)
    } else if let Some(alias) = alias {
        QuerySelection::Alias(alias)
    } else {
        QuerySelection::NoRecords
    }
}

/// The budget of the blocking nameserver query loop behind `lookup_ip`: the
/// resolver timeout less a margin (a tenth of it, at most 100 ms). The loop
/// gives its last query whatever time is left, so with the full timeout it
/// ended together with the `ResolverTimeout` around it, and a lookup whose
/// one family answered while the other timed out was always reported as
/// Timeout instead of returning the answered family.
fn query_budget(timeout: Duration) -> Duration {
    timeout.saturating_sub((timeout / 10).min(Duration::from_millis(100)))
}

/// Runs a blocking system lookup up to `retries + 1` times. A definitive
/// `NoRecords` ends it at once. No further attempt starts once `should_stop`
/// reports that the caller no longer waits for the result.
fn retry_system_lookup(
    retries: u32,
    should_stop: impl Fn() -> bool,
    mut query: impl FnMut() -> Result<LookupIp, DnsError>,
) -> Result<LookupIp, DnsError> {
    let mut last_error = None;
    for _attempt in 0..=retries {
        match query() {
            Ok(result) => return Ok(result),
            Err(error @ DnsError::NoRecords(_)) => return Err(error),
            Err(error) => last_error = Some(error),
        }
        if should_stop() {
            break;
        }
    }
    Err(last_error.unwrap_or(DnsError::Timeout))
}

/// Sets the flag when dropped: the caller of a blocking lookup has stopped
/// waiting for it.
struct AbandonOnDrop(Arc<std::sync::atomic::AtomicBool>);

impl Drop for AbandonOnDrop {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Parses an IP literal, accepting an IPv6 address in URL brackets
/// ("[::1]", RFC 3986 section 3.2.2) as `lookup_ip` callers often pass the
/// host part of a URL.
fn parse_ip_literal(host: &str) -> Option<IpAddr> {
    match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(inner) => inner.parse::<Ipv6Addr>().ok().map(IpAddr::V6),
        None => host.parse().ok(),
    }
}

/// Waits for a blocking lookup unless the calling task is cancelled first,
/// as `net::resolve` does (asupersync-bi2462.119). A cancelled caller gets
/// [`DnsError::Cancelled`] at once; the lookup finishes on its thread and
/// its result is dropped.
async fn unless_cancelled<T>(
    cx: Option<crate::cx::Cx>,
    lookup: impl Future<Output = Result<T, DnsError>>,
) -> Result<T, DnsError> {
    let Some(cx) = cx else {
        return lookup.await;
    };
    let mut lookup = std::pin::pin!(lookup);
    let mut cancelled = std::pin::pin!(cx.cancelled());
    std::future::poll_fn(|task| {
        if cancelled.as_mut().poll(task).is_ready() && cx.checkpoint().is_err() {
            return Poll::Ready(Err(DnsError::Cancelled));
        }
        lookup.as_mut().poll(task)
    })
    .await
}

/// Time-source abstraction for sync DNS query timing.
///
/// br-asupersync-4p1vr3: the legacy sync path (`SyncTimeSource::Wall`)
/// uses `Instant::now()` which violates the I7 ambient-authority
/// invariant (replay-determinism leak). The Cx-threaded path
/// (`SyncTimeSource::CxDerived`) reads from `cx.timer_driver()` so
/// virtual-clock lab tests observe deterministic timeout decisions.
///
/// Kept as a closure pointer rather than a generic to avoid a
/// monomorphization explosion across all DNS query helpers.
enum SyncTimeSource<'a> {
    /// Wall clock via `Instant::now()` — legacy sync APIs.
    Wall {
        started: Instant,
        #[cfg(not(any(test, feature = "test-internals")))]
        marker: std::marker::PhantomData<&'a ()>,
    },
    /// Cx-derived time. The closure must return monotonically
    /// non-decreasing `Time` values across calls within a single query
    /// (asupersync's TimerDriverHandle guarantees this).
    #[cfg(any(test, feature = "test-internals"))]
    CxDerived {
        started: Time,
        now: &'a dyn Fn() -> Time,
    },
}

impl SyncTimeSource<'_> {
    /// Elapsed time since the query started.
    fn elapsed(&self) -> Duration {
        match self {
            Self::Wall { started, .. } => started.elapsed(),
            #[cfg(any(test, feature = "test-internals"))]
            Self::CxDerived { started, now } => {
                let nanos = now().duration_since(*started);
                Duration::from_nanos(nanos)
            }
        }
    }
}

struct SyncDnsQueryContext<'a> {
    timeout: Duration,
    time: SyncTimeSource<'a>,
    entropy: &'a dyn EntropySource,
}

impl Resolver {
    fn query_records_sync(
        name: &str,
        query_type: DnsQueryType,
        nameservers: &[SocketAddr],
        retries: u32,
        timeout: Duration,
        entropy: &dyn EntropySource,
    ) -> Result<Vec<DnsAnswer>, DnsError> {
        let context = SyncDnsQueryContext {
            timeout,
            time: SyncTimeSource::Wall {
                started: Instant::now(),
                #[cfg(not(any(test, feature = "test-internals")))]
                marker: std::marker::PhantomData,
            },
            entropy,
        };
        Self::query_records_inner_sync(name, query_type, nameservers, retries, &context, 0)
    }

    /// Cx-threaded variant of [`Self::query_records_sync`] (br-asupersync-4p1vr3).
    ///
    /// Uses the Cx's timer driver as the time source instead of
    /// `Instant::now()` so virtual-clock lab tests observe deterministic
    /// timeout decisions. Falls back to wall time when the Cx has no
    /// timer driver (mirrors the [`timeout_now`] convention used
    /// throughout this module).
    ///
    /// The cx parameter also enables cancellation propagation: callers
    /// of the higher-level async APIs (lookup_ip etc.) already weave
    /// cancellation in via the Resolver; this lower-level entry point
    /// makes the time path explicit for blocking-pool consumers that
    /// hold a Cx.
    #[cfg(any(test, feature = "test-internals"))]
    #[allow(dead_code)]
    fn query_records_with_cx<'a>(
        cx: &'a crate::cx::Cx,
        name: &str,
        query_type: DnsQueryType,
        nameservers: &[SocketAddr],
        retries: u32,
        timeout: Duration,
        entropy: &'a dyn EntropySource,
    ) -> Result<Vec<DnsAnswer>, DnsError> {
        // Capture the Cx-derived time source. We can't store &Cx inside
        // the closure across an owning-vs-borrow boundary, so the
        // closure reads from cx via the documented timer_driver hook
        // (see `timeout_now` above for the same pattern).
        let now_closure: Box<dyn Fn() -> Time> = match cx.timer_driver() {
            Some(driver) => Box::new(move || driver.now()),
            None => Box::new(crate::time::wall_now),
        };
        // SAFETY (lifetime): now_closure outlives the context (both end
        // at this fn's return). The reference inside SyncTimeSource
        // borrows from now_closure, which sits on this stack.
        let now_ref: &dyn Fn() -> Time = &*now_closure;
        let started = now_ref();
        let context = SyncDnsQueryContext {
            timeout,
            time: SyncTimeSource::CxDerived {
                started,
                now: now_ref,
            },
            entropy,
        };
        Self::query_records_inner_sync(name, query_type, nameservers, retries, &context, 0)
    }

    fn query_records_inner_sync(
        name: &str,
        query_type: DnsQueryType,
        nameservers: &[SocketAddr],
        retries: u32,
        context: &SyncDnsQueryContext<'_>,
        cname_depth: usize,
    ) -> Result<Vec<DnsAnswer>, DnsError> {
        if nameservers.is_empty() {
            return Err(DnsError::Io("no DNS nameservers configured".to_string()));
        }
        if cname_depth > 8 {
            return Err(DnsError::ServerError(
                "DNS CNAME chain exceeded recursion limit".to_string(),
            ));
        }

        let mut last_error = None;
        let mut saw_no_records = false;
        let mut deferred_alias = None;
        // A server that answered NXDOMAIN, no data or an alias has answered:
        // asking it again cannot change that. Only servers that failed or
        // timed out are retried, and the loop ends once every server has
        // answered.
        let mut answered = vec![false; nameservers.len()];

        for attempt in 0..=retries {
            for (index, nameserver) in nameservers.iter().copied().enumerate() {
                if answered[index] {
                    continue;
                }
                let remaining = context
                    .timeout
                    .checked_sub(context.time.elapsed())
                    .unwrap_or(Duration::ZERO);
                if remaining.is_zero() {
                    return Err(DnsError::Timeout);
                }

                // Share the remaining time among the queries this loop may
                // still send, so later queries do not get ever smaller slices.
                let unanswered = answered.iter().filter(|done| !**done).count();
                let left_in_pass = answered[index..].iter().filter(|done| !**done).count();
                let queries_left =
                    left_in_pass.saturating_add((retries - attempt) as usize * unanswered);
                let query_timeout = per_attempt_timeout(remaining, queries_left).min(remaining);
                let query_id = dns_query_id(context.entropy);
                let query = build_dns_query(name, query_type, query_id)?;

                match query_nameserver(nameserver, &query, query_id, query_timeout) {
                    Ok(response) => match response.rcode {
                        0 => match select_records_for_query(name, query_type, &response.answers) {
                            QuerySelection::Records(records) => return Ok(records),
                            QuerySelection::Alias(alias) => {
                                if deferred_alias.is_none() {
                                    deferred_alias = Some(alias);
                                }
                                answered[index] = true;
                            }
                            QuerySelection::NoRecords => {
                                saw_no_records = true;
                                answered[index] = true;
                            }
                        },
                        3 => {
                            saw_no_records = true;
                            answered[index] = true;
                        }
                        rcode => {
                            last_error = Some(DnsError::ServerError(format!(
                                "DNS server returned rcode {rcode} for {name}"
                            )));
                        }
                    },
                    Err(DnsError::Timeout) => {
                        last_error = Some(DnsError::Timeout);
                    }
                    Err(err) => {
                        last_error = Some(err);
                    }
                }
            }
            if answered.iter().all(|done| *done) {
                break;
            }
        }

        if let Some(alias) = deferred_alias {
            return Self::query_records_inner_sync(
                &alias,
                query_type,
                nameservers,
                retries,
                context,
                cname_depth + 1,
            );
        }
        if saw_no_records {
            return Err(DnsError::NoRecords(name.to_string()));
        }

        Err(last_error.unwrap_or(DnsError::Timeout))
    }

    fn query_ip_with_nameservers_sync(
        host: &str,
        nameservers: &[SocketAddr],
        retries: u32,
        timeout: Duration,
        entropy: &dyn EntropySource,
    ) -> Result<LookupIp, DnsError> {
        let context = SyncDnsQueryContext {
            timeout,
            time: SyncTimeSource::Wall {
                started: Instant::now(),
                #[cfg(not(any(test, feature = "test-internals")))]
                marker: std::marker::PhantomData,
            },
            entropy,
        };
        let mut addresses = Vec::new();
        let mut ttl = None;
        let mut last_error = None;

        for query_type in [DnsQueryType::Aaaa, DnsQueryType::A] {
            match Self::query_records_inner_sync(
                host,
                query_type,
                nameservers,
                retries,
                &context,
                0,
            ) {
                Ok(records) => {
                    for record in records {
                        ttl = Some(
                            ttl.map_or(record.ttl, |current: Duration| current.min(record.ttl)),
                        );
                        match record.data {
                            DnsRecordData::A(ip) => {
                                let addr = IpAddr::V4(ip);
                                if !addresses.contains(&addr) {
                                    addresses.push(addr);
                                }
                            }
                            DnsRecordData::Aaaa(ip) => {
                                let addr = IpAddr::V6(ip);
                                if !addresses.contains(&addr) {
                                    addresses.push(addr);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Err(DnsError::NoRecords(_)) => {}
                Err(err) => last_error = Some(err),
            }
        }

        if addresses.is_empty() {
            Err(last_error.unwrap_or_else(|| DnsError::NoRecords(host.to_string())))
        } else if last_error.is_some() {
            // One family answered and the other failed (timeout, SERVFAIL).
            // Return what was found, with TTL 0 so it is not cached: caching
            // it would hide the missing family for the whole TTL.
            Ok(LookupIp::new(addresses, Duration::ZERO))
        } else {
            Ok(LookupIp::new(
                addresses,
                ttl.unwrap_or_else(|| Duration::from_secs(0)),
            ))
        }
    }
}

#[cfg(test)]
#[path = "resolver_inline_tests.rs"]
mod tests;
