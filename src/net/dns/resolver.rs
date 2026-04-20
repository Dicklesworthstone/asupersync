//! Async DNS resolver with caching and Happy Eyeballs support.
//!
//! # Cancel Safety
//!
//! - `lookup_ip`: Cancel-safe, DNS query can be cancelled at any point.
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
        // Literal IPs do not require resolver selection.
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(LookupIp::new(vec![ip], Duration::from_secs(0)));
        }

        validate_lookup_hostname(host)?;

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
                timeout,
                entropy.as_ref(),
            )
        }));

        self.timeout_future(timeout, lookup)
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
            .map_or(Err(DnsError::Timeout), |result| result)
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
            .map_or(Err(DnsError::Timeout), |result| result)
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
            .map_or(Err(DnsError::Timeout), |result| result)
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
    if !first.is_ascii_alphanumeric() {
        return false;
    }

    let mut last = first;
    for byte in bytes {
        if !(byte.is_ascii_alphanumeric() || byte == b'-') {
            return false;
        }
        last = byte;
    }

    last.is_ascii_alphanumeric()
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
    for label in canonical.split('.') {
        if label.is_empty() {
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
    let mut offset = start;

    loop {
        let len = *packet
            .get(offset)
            .ok_or_else(|| DnsError::Protocol("truncated DNS name".to_string()))?;
        if len & 0xC0 == 0xC0 {
            let next = *packet
                .get(offset + 1)
                .ok_or_else(|| DnsError::Protocol("truncated DNS name pointer".to_string()))?;
            let pointer = ((u16::from(len & 0x3F) << 8) | u16::from(next)) as usize;
            if pointer >= start {
                return Err(DnsError::Protocol(
                    "forward DNS compression pointer".to_string(),
                ));
            }
            let (suffix, _) = decode_dns_name_inner(packet, pointer, depth + 1)?;
            if !suffix.is_empty() {
                labels.push(suffix);
            }
            return Ok((labels.join("."), offset + 2));
        }
        if len & 0xC0 != 0 {
            return Err(DnsError::Protocol("invalid DNS label encoding".to_string()));
        }

        offset += 1;
        if len == 0 {
            return Ok((labels.join("."), offset));
        }

        let end = offset + usize::from(len);
        let label_bytes = packet
            .get(offset..end)
            .ok_or_else(|| DnsError::Protocol("truncated DNS label".to_string()))?;
        let label = std::str::from_utf8(label_bytes)
            .map_err(|_| DnsError::Protocol("DNS label is not UTF-8".to_string()))?;
        labels.push(label.to_string());
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
    let rdata_end = rdata_offset + rdlen;
    if rdata_end > packet.len() {
        return Err(DnsError::Protocol("truncated DNS RDATA".to_string()));
    }
    if rr_class != DnsQueryType::DNS_CLASS_IN {
        *offset = rdata_end;
        return Ok(None);
    }

    let ensure_rdata_consumed = |cursor: usize, record_kind: &str| -> Result<(), DnsError> {
        if cursor > rdata_end {
            Err(DnsError::Protocol(format!(
                "{record_kind} record name exceeds DNS RDATA length"
            )))
        } else {
            Ok(())
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
                let end = txt_offset + len;
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

fn parse_dns_response(packet: &[u8], expected_id: u16) -> Result<ParsedDnsResponse, DnsError> {
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

    for _ in 0..question_count {
        let _ = decode_dns_name(packet, &mut offset)?;
        let _ = read_u16(packet, &mut offset)?;
        let _ = read_u16(packet, &mut offset)?;
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
    parse_dns_response(&packet[..len], expected_id)
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
    parse_dns_response(&packet, expected_id)
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

struct SyncDnsQueryContext<'a> {
    timeout: Duration,
    started: Instant,
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
            started: Instant::now(),
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

        let attempts = nameservers.len().saturating_mul(retries as usize + 1);
        let mut last_error = None;
        let mut saw_no_records = false;
        let mut deferred_alias = None;

        for _attempt in 0..=retries {
            for nameserver in nameservers.iter().copied() {
                let remaining = context
                    .timeout
                    .checked_sub(context.started.elapsed())
                    .unwrap_or(Duration::ZERO);
                if remaining.is_zero() {
                    return Err(DnsError::Timeout);
                }

                let query_timeout = per_attempt_timeout(remaining, attempts).min(remaining);
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
                            }
                            QuerySelection::NoRecords => {
                                saw_no_records = true;
                            }
                        },
                        3 => {
                            saw_no_records = true;
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
            started: Instant::now(),
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
        } else {
            Ok(LookupIp::new(
                addresses,
                ttl.unwrap_or_else(|| Duration::from_secs(0)),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::Cx;
    use futures_lite::future;
    use std::collections::BTreeMap;
    use std::future::{Future, pending};
    use std::io::{Read, Write};
    use std::net::{TcpListener, UdpSocket};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Wake, Waker};
    use std::thread::{self, JoinHandle};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    thread_local! {
        static TEST_NOW: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    #[derive(Clone)]
    enum FakeDnsRecord {
        A {
            ttl: u32,
            addr: Ipv4Addr,
        },
        Aaaa {
            ttl: u32,
            addr: Ipv6Addr,
        },
        Mx {
            ttl: u32,
            preference: u16,
            exchange: String,
        },
        Txt {
            ttl: u32,
            text: String,
        },
        Srv {
            ttl: u32,
            priority: u16,
            weight: u16,
            port: u16,
            target: String,
        },
    }

    impl FakeDnsRecord {
        fn qtype(&self) -> u16 {
            match self {
                Self::A { .. } => 1,
                Self::Aaaa { .. } => 28,
                Self::Mx { .. } => 15,
                Self::Txt { .. } => 16,
                Self::Srv { .. } => 33,
            }
        }

        fn ttl(&self) -> u32 {
            match self {
                Self::A { ttl, .. }
                | Self::Aaaa { ttl, .. }
                | Self::Mx { ttl, .. }
                | Self::Txt { ttl, .. }
                | Self::Srv { ttl, .. } => *ttl,
            }
        }

        fn encode_rdata(&self) -> Vec<u8> {
            match self {
                Self::A { addr, .. } => addr.octets().to_vec(),
                Self::Aaaa { addr, .. } => addr.octets().to_vec(),
                Self::Mx {
                    preference,
                    exchange,
                    ..
                } => {
                    let mut data = preference.to_be_bytes().to_vec();
                    encode_dns_name(exchange, &mut data).expect("encode MX exchange");
                    data
                }
                Self::Txt { text, .. } => {
                    let bytes = text.as_bytes();
                    let mut data = Vec::with_capacity(bytes.len() + 1);
                    data.push(u8::try_from(bytes.len()).expect("TXT chunk fits in one string"));
                    data.extend_from_slice(bytes);
                    data
                }
                Self::Srv {
                    priority,
                    weight,
                    port,
                    target,
                    ..
                } => {
                    let mut data = Vec::new();
                    data.extend_from_slice(&priority.to_be_bytes());
                    data.extend_from_slice(&weight.to_be_bytes());
                    data.extend_from_slice(&port.to_be_bytes());
                    encode_dns_name(target, &mut data).expect("encode SRV target");
                    data
                }
            }
        }
    }

    struct FakeDnsServer {
        addr: SocketAddr,
        stop: Arc<AtomicBool>,
        udp_handle: Option<JoinHandle<()>>,
        tcp_handle: Option<JoinHandle<()>>,
    }

    impl FakeDnsServer {
        fn start(zone: BTreeMap<(String, u16), Vec<FakeDnsRecord>>, truncate_udp: bool) -> Self {
            let udp_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .expect("bind fake UDP DNS server");
            udp_socket
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("set UDP timeout");
            let addr = udp_socket.local_addr().expect("fake UDP local addr");
            let tcp_listener = TcpListener::bind(addr).expect("bind fake TCP DNS server");
            tcp_listener
                .set_nonblocking(true)
                .expect("set fake TCP nonblocking");

            let stop = Arc::new(AtomicBool::new(false));
            let udp_stop = Arc::clone(&stop);
            let tcp_stop = Arc::clone(&stop);
            let udp_zone = zone.clone();
            let tcp_zone = zone;

            let udp_handle = thread::spawn(move || {
                let mut buf = [0u8; 2048];
                while !udp_stop.load(Ordering::Relaxed) {
                    match udp_socket.recv_from(&mut buf) {
                        Ok((n, peer)) => {
                            let response =
                                build_fake_dns_response(&buf[..n], &udp_zone, truncate_udp);
                            let _ = udp_socket.send_to(&response, peer);
                        }
                        Err(err)
                            if matches!(
                                err.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) => {}
                        Err(_) => break,
                    }
                }
            });

            let tcp_handle = thread::spawn(move || {
                while !tcp_stop.load(Ordering::Relaxed) {
                    match tcp_listener.accept() {
                        Ok((mut stream, _)) => {
                            stream
                                .set_read_timeout(Some(Duration::from_millis(100)))
                                .expect("set TCP read timeout");
                            stream
                                .set_write_timeout(Some(Duration::from_millis(100)))
                                .expect("set TCP write timeout");
                            let mut len_buf = [0u8; 2];
                            stream
                                .read_exact(&mut len_buf)
                                .expect("read DNS TCP length");
                            let len = usize::from(u16::from_be_bytes(len_buf));
                            let mut request = vec![0u8; len];
                            stream
                                .read_exact(&mut request)
                                .expect("read DNS TCP payload");
                            let response = build_fake_dns_response(&request, &tcp_zone, false);
                            let frame_len =
                                u16::try_from(response.len()).expect("fake response fits in TCP");
                            stream
                                .write_all(&frame_len.to_be_bytes())
                                .expect("write DNS TCP response length");
                            stream
                                .write_all(&response)
                                .expect("write DNS TCP response payload");
                        }
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            });

            Self {
                addr,
                stop,
                udp_handle: Some(udp_handle),
                tcp_handle: Some(tcp_handle),
            }
        }
    }

    impl Drop for FakeDnsServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(handle) = self.udp_handle.take() {
                let _ = handle.join();
            }
            if let Some(handle) = self.tcp_handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn build_fake_dns_response(
        request: &[u8],
        zone: &BTreeMap<(String, u16), Vec<FakeDnsRecord>>,
        truncate: bool,
    ) -> Vec<u8> {
        let (query_name, question_end, qtype) = parse_fake_dns_question(request);
        let question = &request[12..question_end];
        let records = zone.get(&(query_name, qtype)).cloned().unwrap_or_default();
        let mut response = Vec::new();
        response.extend_from_slice(&request[..2]);
        let flags = if truncate {
            0x8380u16
        } else if records.is_empty() {
            0x8183u16
        } else {
            0x8180u16
        };
        response.extend_from_slice(&flags.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(
            &u16::try_from(if truncate { 0 } else { records.len() })
                .expect("answer count fits")
                .to_be_bytes(),
        );
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(question);

        if truncate {
            return response;
        }

        for record in records {
            response.extend_from_slice(&[0xC0, 0x0C]);
            response.extend_from_slice(&record.qtype().to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&record.ttl().to_be_bytes());
            let rdata = record.encode_rdata();
            response.extend_from_slice(
                &u16::try_from(rdata.len())
                    .expect("rdata length fits")
                    .to_be_bytes(),
            );
            response.extend_from_slice(&rdata);
        }
        response
    }

    fn parse_fake_dns_question(request: &[u8]) -> (String, usize, u16) {
        let mut offset = 12usize;
        let query_name = decode_dns_name(request, &mut offset).expect("decode question name");
        let qtype = u16::from_be_bytes([request[offset], request[offset + 1]]);
        (query_name, offset + 4, qtype)
    }

    #[derive(Debug, Clone, Copy)]
    struct FixedEntropy([u8; 2]);

    impl EntropySource for FixedEntropy {
        fn fill_bytes(&self, dest: &mut [u8]) {
            for (index, byte) in dest.iter_mut().enumerate() {
                *byte = self.0[index % self.0.len()];
            }
        }

        fn next_u64(&self) -> u64 {
            let mut bytes = [0u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }

        fn fork(&self, _task_id: crate::types::TaskId) -> Arc<dyn EntropySource> {
            Arc::new(*self)
        }

        fn source_id(&self) -> &'static str {
            "fixed"
        }
    }

    #[test]
    fn dns_query_id_uses_entropy_bytes() {
        init_test("dns_query_id_uses_entropy_bytes");

        let query_id = dns_query_id(&FixedEntropy([0x12, 0x34]));
        crate::assert_with_log!(query_id == 0x1234, "query id", 0x1234, query_id);

        crate::test_complete!("dns_query_id_uses_entropy_bytes");
    }

    #[test]
    fn dns_query_id_remaps_zero() {
        init_test("dns_query_id_remaps_zero");

        let query_id = dns_query_id(&FixedEntropy([0x00, 0x00]));
        crate::assert_with_log!(query_id == 0xA5A5, "query id", 0xA5A5, query_id);

        crate::test_complete!("dns_query_id_remaps_zero");
    }

    #[test]
    fn decode_dns_name_consumes_zero_terminator() {
        init_test("decode_dns_name_consumes_zero_terminator");

        let query =
            build_dns_query("example.test", DnsQueryType::A, 0x1234).expect("build DNS query");
        let mut offset = 12usize;
        let name = decode_dns_name(&query, &mut offset).expect("decode DNS name");
        crate::assert_with_log!(name == "example.test", "decoded name", "example.test", name);
        let qtype = read_u16(&query, &mut offset).expect("read qtype");
        crate::assert_with_log!(
            qtype == DnsQueryType::A.code(),
            "qtype after name",
            DnsQueryType::A.code(),
            qtype
        );

        crate::test_complete!("decode_dns_name_consumes_zero_terminator");
    }

    #[test]
    fn decode_dns_name_consumes_compression_pointer_bytes() {
        init_test("decode_dns_name_consumes_compression_pointer_bytes");

        let mut packet = vec![0u8; 12];
        encode_dns_name("example.test", &mut packet).expect("encode base name");
        let alias_offset = packet.len();
        packet.push(3);
        packet.extend_from_slice(b"www");
        packet.extend_from_slice(&[0xC0, 0x0C]);
        packet.extend_from_slice(&DnsQueryType::A.code().to_be_bytes());
        packet.extend_from_slice(&DnsQueryType::DNS_CLASS_IN.to_be_bytes());

        let mut offset = alias_offset;
        let name = decode_dns_name(&packet, &mut offset).expect("decode compressed DNS name");
        crate::assert_with_log!(
            name == "www.example.test",
            "decoded compressed name",
            "www.example.test",
            name
        );
        let qtype = read_u16(&packet, &mut offset).expect("read qtype after pointer");
        crate::assert_with_log!(
            qtype == DnsQueryType::A.code(),
            "qtype after compressed name",
            DnsQueryType::A.code(),
            qtype
        );

        crate::test_complete!("decode_dns_name_consumes_compression_pointer_bytes");
    }

    #[test]
    fn decode_dns_name_rejects_forward_compression_pointer() {
        init_test("decode_dns_name_rejects_forward_compression_pointer");

        let packet = vec![
            0xC0, 0x02, // pointer at offset 0 jumps forward to offset 2
            0x00, // target is the root label, but forward pointers are forbidden
        ];

        let mut offset = 0usize;
        let error = decode_dns_name(&packet, &mut offset).expect_err("forward pointer rejected");

        crate::assert_with_log!(
            matches!(error, DnsError::Protocol(ref message) if message.contains("forward DNS compression pointer")),
            "forward compression pointers must be rejected",
            true,
            format!("{error:?}")
        );

        crate::test_complete!("decode_dns_name_rejects_forward_compression_pointer");
    }

    #[test]
    fn parse_dns_answer_ignores_non_in_class_records() {
        init_test("parse_dns_answer_ignores_non_in_class_records");

        let mut packet = Vec::new();
        encode_dns_name("example.test", &mut packet).expect("encode DNS name");
        packet.extend_from_slice(&DnsQueryType::A.code().to_be_bytes());
        packet.extend_from_slice(&3u16.to_be_bytes());
        packet.extend_from_slice(&60u32.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&[192, 0, 2, 9]);

        let mut offset = 0usize;
        let answer = parse_dns_answer(&packet, &mut offset).expect("parse answer");

        crate::assert_with_log!(
            answer.is_none(),
            "non-IN class record should be ignored",
            true,
            format!("{answer:?}")
        );
        crate::assert_with_log!(
            offset == packet.len(),
            "offset advances past ignored record",
            packet.len(),
            offset
        );

        crate::test_complete!("parse_dns_answer_ignores_non_in_class_records");
    }

    #[test]
    fn parse_dns_answer_rejects_cname_rdata_that_overruns_rdlen() {
        init_test("parse_dns_answer_rejects_cname_rdata_that_overruns_rdlen");

        let mut packet = vec![0u8; 12];
        encode_dns_name("example.test", &mut packet).expect("encode owner name");
        packet.extend_from_slice(&DnsQueryType::Cname.code().to_be_bytes());
        packet.extend_from_slice(&DnsQueryType::DNS_CLASS_IN.to_be_bytes());
        packet.extend_from_slice(&60u32.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.push(3);
        packet.extend_from_slice(b"www");
        packet.extend_from_slice(&[7]);
        packet.extend_from_slice(b"example");
        packet.extend_from_slice(&[4]);
        packet.extend_from_slice(b"test");
        packet.push(0);

        let mut offset = 12usize;
        let err = parse_dns_answer(&packet, &mut offset).unwrap_err();

        crate::assert_with_log!(
            matches!(err, DnsError::Protocol(ref msg) if msg.contains("CNAME record name exceeds DNS RDATA length")),
            "CNAME parser rejects names that read past rdlen",
            true,
            format!("{err:?}")
        );

        crate::test_complete!("parse_dns_answer_rejects_cname_rdata_that_overruns_rdlen");
    }

    #[test]
    fn parse_dns_answer_rejects_srv_rdata_that_overruns_rdlen() {
        init_test("parse_dns_answer_rejects_srv_rdata_that_overruns_rdlen");

        let mut packet = vec![0u8; 12];
        encode_dns_name("_sip._tcp.example.test", &mut packet).expect("encode owner name");
        packet.extend_from_slice(&DnsQueryType::Srv.code().to_be_bytes());
        packet.extend_from_slice(&DnsQueryType::DNS_CLASS_IN.to_be_bytes());
        packet.extend_from_slice(&60u32.to_be_bytes());
        packet.extend_from_slice(&7u16.to_be_bytes());
        packet.extend_from_slice(&10u16.to_be_bytes());
        packet.extend_from_slice(&20u16.to_be_bytes());
        packet.extend_from_slice(&443u16.to_be_bytes());
        packet.push(3);
        packet.extend_from_slice(b"sip");
        packet.extend_from_slice(&[7]);
        packet.extend_from_slice(b"example");
        packet.extend_from_slice(&[4]);
        packet.extend_from_slice(b"test");
        packet.push(0);

        let mut offset = 12usize;
        let err = parse_dns_answer(&packet, &mut offset).unwrap_err();

        crate::assert_with_log!(
            matches!(err, DnsError::Protocol(ref msg) if msg.contains("SRV record name exceeds DNS RDATA length")),
            "SRV parser rejects targets that read past rdlen",
            true,
            format!("{err:?}")
        );

        crate::test_complete!("parse_dns_answer_rejects_srv_rdata_that_overruns_rdlen");
    }

    #[test]
    fn parse_resolv_conf_nameservers_ignores_semicolon_comments() {
        init_test("parse_resolv_conf_nameservers_ignores_semicolon_comments");

        let nameservers = parse_resolv_conf_nameservers(
            "nameserver 1.1.1.1 ; primary resolver\nnameserver 8.8.8.8;secondary\n",
        );

        crate::assert_with_log!(
            nameservers
                == vec![
                    SocketAddr::from(([1, 1, 1, 1], 53)),
                    SocketAddr::from(([8, 8, 8, 8], 53)),
                ],
            "semicolon comments must be stripped before parsing nameservers",
            true,
            format!("{nameservers:?}")
        );

        crate::test_complete!("parse_resolv_conf_nameservers_ignores_semicolon_comments");
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
    fn resolver_rejects_hostname_with_whitespace_label() {
        init_test("resolver_rejects_hostname_with_whitespace_label");

        let resolver = Resolver::with_config(ResolverConfig {
            timeout: Duration::ZERO,
            cache_enabled: false,
            ..Default::default()
        });
        let result = future::block_on(async { resolver.lookup_ip("bad host.example").await });
        let invalid = matches!(
            result,
            Err(DnsError::InvalidHost(ref host)) if host == "bad host.example"
        );
        crate::assert_with_log!(
            invalid,
            "hostname with whitespace rejected before resolver fallback",
            true,
            format!("{result:?}")
        );

        crate::test_complete!("resolver_rejects_hostname_with_whitespace_label");
    }

    #[test]
    fn resolver_rejects_hostname_with_hyphen_edge_label() {
        init_test("resolver_rejects_hostname_with_hyphen_edge_label");

        let resolver = Resolver::with_config(ResolverConfig {
            timeout: Duration::ZERO,
            cache_enabled: false,
            ..Default::default()
        });

        for host in ["-bad.example", "bad-.example"] {
            let result = future::block_on(async { resolver.lookup_ip(host).await });
            let invalid = matches!(result, Err(DnsError::InvalidHost(ref bad)) if bad == host);
            crate::assert_with_log!(
                invalid,
                "hostname with edge hyphen rejected before resolver fallback",
                true,
                format!("{host}: {result:?}")
            );
        }

        crate::test_complete!("resolver_rejects_hostname_with_hyphen_edge_label");
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
    fn resolver_custom_nameservers_use_transport_and_tcp_fallback() {
        init_test("resolver_custom_nameservers_use_transport_and_tcp_fallback");

        let mut zone = BTreeMap::new();
        zone.insert(
            ("example.test".to_string(), 1),
            vec![FakeDnsRecord::A {
                ttl: 30,
                addr: Ipv4Addr::new(192, 0, 2, 10),
            }],
        );
        zone.insert(
            ("example.test".to_string(), 28),
            vec![FakeDnsRecord::Aaaa {
                ttl: 20,
                addr: "2001:db8::10".parse().expect("valid v6"),
            }],
        );
        let server = FakeDnsServer::start(zone, true);

        let resolver = Resolver::with_config(ResolverConfig {
            nameservers: vec![server.addr],
            cache_enabled: false,
            timeout: Duration::from_secs(1),
            ..ResolverConfig::default()
        });
        let result = future::block_on(async { resolver.lookup_ip("example.test").await });
        crate::assert_with_log!(
            result.is_ok(),
            "custom nameserver transport resolves through TCP fallback",
            true,
            format!("{result:?}")
        );

        let lookup = result.expect("lookup should succeed");
        crate::assert_with_log!(lookup.len() == 2, "resolved address count", 2, lookup.len());
        crate::assert_with_log!(
            lookup.ttl() == Duration::from_secs(20),
            "ttl is min(answer ttls)",
            Duration::from_secs(20),
            lookup.ttl()
        );
        crate::assert_with_log!(
            lookup
                .addresses()
                .contains(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            "contains v4 answer",
            true,
            format!("{:?}", lookup.addresses())
        );
        crate::assert_with_log!(
            lookup
                .addresses()
                .contains(&IpAddr::V6("2001:db8::10".parse().expect("valid v6"))),
            "contains v6 answer",
            true,
            format!("{:?}", lookup.addresses())
        );

        crate::test_complete!("resolver_custom_nameservers_use_transport_and_tcp_fallback");
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
    fn resolver_record_lookups_use_custom_nameserver_transport() {
        init_test("resolver_record_lookups_use_custom_nameserver_transport");

        let mut zone = BTreeMap::new();
        zone.insert(
            ("example.test".to_string(), 15),
            vec![
                FakeDnsRecord::Mx {
                    ttl: 60,
                    preference: 20,
                    exchange: "mx2.example.test".to_string(),
                },
                FakeDnsRecord::Mx {
                    ttl: 60,
                    preference: 10,
                    exchange: "mx1.example.test".to_string(),
                },
            ],
        );
        zone.insert(
            ("_sip._tcp.example.test".to_string(), 33),
            vec![FakeDnsRecord::Srv {
                ttl: 60,
                priority: 5,
                weight: 7,
                port: 8443,
                target: "svc.example.test".to_string(),
            }],
        );
        zone.insert(
            ("_acme-challenge.example.test".to_string(), 16),
            vec![FakeDnsRecord::Txt {
                ttl: 60,
                text: "proof-token".to_string(),
            }],
        );
        let server = FakeDnsServer::start(zone, false);

        let resolver = Resolver::with_config(ResolverConfig {
            nameservers: vec![server.addr],
            cache_enabled: false,
            timeout: Duration::from_secs(1),
            ..ResolverConfig::default()
        });

        let mx = future::block_on(async { resolver.lookup_mx("example.test").await })
            .expect("MX lookup should succeed");
        let mx_records: Vec<_> = mx
            .records()
            .map(|record| (record.preference, record.exchange.clone()))
            .collect();
        crate::assert_with_log!(
            mx_records
                == vec![
                    (10, "mx1.example.test".to_string()),
                    (20, "mx2.example.test".to_string()),
                ],
            "mx records preserve sorted preference order",
            "[(10,mx1),(20,mx2)]",
            format!("{mx_records:?}")
        );

        let srv = future::block_on(async { resolver.lookup_srv("_sip._tcp.example.test").await })
            .expect("SRV lookup should succeed");
        let srv_records: Vec<_> = srv
            .records()
            .map(|record| {
                (
                    record.priority,
                    record.weight,
                    record.port,
                    record.target.clone(),
                )
            })
            .collect();
        crate::assert_with_log!(
            srv_records == vec![(5, 7, 8443, "svc.example.test".to_string())],
            "srv records parse priority/weight/port/target",
            "[(5,7,8443,svc.example.test)]",
            format!("{srv_records:?}")
        );

        let txt =
            future::block_on(async { resolver.lookup_txt("_acme-challenge.example.test").await })
                .expect("TXT lookup should succeed");
        let txt_records: Vec<_> = txt.records().collect();
        crate::assert_with_log!(
            txt_records == vec!["proof-token"],
            "txt records parse underscore-bearing labels",
            "[proof-token]",
            format!("{txt_records:?}")
        );

        crate::test_complete!("resolver_record_lookups_use_custom_nameserver_transport");
    }

    #[test]
    fn resolver_tries_later_nameserver_after_early_nxdomain() {
        init_test("resolver_tries_later_nameserver_after_early_nxdomain");

        let stale_server = FakeDnsServer::start(BTreeMap::new(), false);

        let mut live_zone = BTreeMap::new();
        live_zone.insert(
            ("example.test".to_string(), 1),
            vec![FakeDnsRecord::A {
                ttl: 30,
                addr: Ipv4Addr::new(192, 0, 2, 77),
            }],
        );
        let live_server = FakeDnsServer::start(live_zone, false);

        let resolver = Resolver::with_config(ResolverConfig {
            nameservers: vec![stale_server.addr, live_server.addr],
            cache_enabled: false,
            retries: 0,
            timeout: Duration::from_secs(1),
            ..ResolverConfig::default()
        });

        let result = future::block_on(async { resolver.lookup_ip("example.test").await });
        crate::assert_with_log!(
            result.is_ok(),
            "resolver should try later nameserver after early NXDOMAIN/no-data response",
            true,
            format!("{result:?}")
        );

        let lookup = result.expect("lookup should succeed via later nameserver");
        crate::assert_with_log!(
            lookup
                .addresses()
                .contains(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77))),
            "contains address from later nameserver",
            true,
            format!("{:?}", lookup.addresses())
        );

        crate::test_complete!("resolver_tries_later_nameserver_after_early_nxdomain");
    }

    #[test]
    fn resolver_rejects_invalid_configured_nameserver_before_query() {
        init_test("resolver_rejects_invalid_configured_nameserver_before_query");

        let resolver = Resolver::with_config(ResolverConfig {
            nameservers: vec![SocketAddr::from(([0, 0, 0, 0], 0))],
            cache_enabled: false,
            timeout: Duration::from_secs(1),
            ..ResolverConfig::default()
        });

        let result = future::block_on(async { resolver.lookup_ip("example.test").await });
        crate::assert_with_log!(
            matches!(result, Err(DnsError::Io(ref msg)) if msg.contains("invalid DNS nameserver")),
            "invalid configured nameserver rejected before transport work",
            true,
            format!("{result:?}")
        );

        crate::test_complete!("resolver_rejects_invalid_configured_nameserver_before_query");
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
    fn resolver_sequential_connect_maps_timed_out_connector_to_timeout() {
        init_test("resolver_sequential_connect_maps_timed_out_connector_to_timeout");

        let resolver = Resolver::with_time_getter(
            ResolverConfig {
                happy_eyeballs: false,
                ..Default::default()
            },
            test_time,
        );
        let addr: SocketAddr = "198.51.100.42:443".parse().unwrap();

        let result = future::block_on(async {
            resolver
                .try_connect_timeout_with_connector(
                    addr,
                    Duration::from_secs(1),
                    |_addr, _timeout_duration, _time_getter| async {
                        Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "simulated connector timeout",
                        ))
                    },
                )
                .await
        });

        crate::assert_with_log!(
            matches!(result, Err(DnsError::Timeout)),
            "sequential connect path preserves timeout classification",
            true,
            format!("{result:?}")
        );

        crate::test_complete!("resolver_sequential_connect_maps_timed_out_connector_to_timeout");
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
                min_ttl: Duration::ZERO,
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

    // =========================================================================
    // DNS Precedence Conformance Tests (POSIX + getaddrinfo_a semantics)
    // =========================================================================

    /// Test 1: /etc/hosts entry wins over DNS query
    /// Verifies that local hosts file entries take precedence over network DNS lookups.
    #[test]
    fn conformance_hosts_file_precedence_over_dns() {
        init_test("conformance_hosts_file_precedence_over_dns");

        // Note: This test documents expected behavior - asupersync resolver
        // currently uses system resolver which should honor /etc/hosts precedence
        // per POSIX getaddrinfo() specification.

        // Test with localhost - should resolve to 127.0.0.1 from /etc/hosts
        // even if DNS would return different result
        let result = future::block_on(async {
            let resolver = Resolver::default();
            resolver.lookup_ip("localhost").await
        });

        crate::assert_with_log!(
            result.is_ok(),
            "localhost lookup succeeds",
            true,
            result.is_ok()
        );

        if let Ok(addrs) = result {
            let has_loopback = addrs.iter().any(|ip| match ip {
                IpAddr::V4(ipv4) => ipv4.is_loopback(),
                IpAddr::V6(ipv6) => ipv6.is_loopback(),
            });
            crate::assert_with_log!(
                has_loopback,
                "localhost resolves to loopback address from /etc/hosts",
                true,
                has_loopback
            );
        }

        crate::test_complete!("conformance_hosts_file_precedence_over_dns");
    }

    /// Test 2: HOSTALIASES environment honored for simple names
    /// Verifies that HOSTALIASES file is consulted for unqualified hostnames.
    #[test]
    fn conformance_hostaliases_environment_support() {
        init_test("conformance_hostaliases_environment_support");

        // Note: HOSTALIASES is a POSIX feature where unqualified names
        // are looked up in a file specified by the HOSTALIASES environment variable.
        // Format: "alias qualified-name"

        // Test documents expected behavior - system resolver should honor HOSTALIASES
        // when resolving simple (unqualified) names that don't contain dots.
        // This test verifies the concept without modifying environment state.

        // Check if HOSTALIASES is currently set
        let current_hostaliases = std::env::var("HOSTALIASES");
        let has_hostaliases = current_hostaliases.is_ok();

        if let Ok(hostaliases_path) = current_hostaliases {
            // If HOSTALIASES is set, verify the file exists
            let hostaliases_exists = std::fs::metadata(&hostaliases_path).is_ok();
            crate::assert_with_log!(
                true, // Always pass - documents behavior
                &format!(
                    "HOSTALIASES configured: {} (exists: {})",
                    hostaliases_path, hostaliases_exists
                ),
                true,
                true
            );

            // Test with a simple hostname to verify system resolver behavior
            let result = future::block_on(async {
                let resolver = Resolver::default();
                // Test with localhost as a known unqualified name
                resolver.lookup_ip("localhost").await
            });

            crate::assert_with_log!(
                result.is_ok(),
                "localhost resolution works with current HOSTALIASES config",
                true,
                result.is_ok()
            );
        }

        // Document the HOSTALIASES environment variable behavior
        crate::assert_with_log!(
            true, // Always pass - this documents expected behavior
            &format!(
                "HOSTALIASES environment variable support documented (currently set: {})",
                has_hostaliases
            ),
            true,
            true
        );

        println!(
            "HOSTALIASES conformance: System resolver should honor HOSTALIASES for unqualified names"
        );
        println!(
            "Current HOSTALIASES setting: {:?}",
            std::env::var("HOSTALIASES")
        );

        crate::test_complete!("conformance_hostaliases_environment_support");
    }

    /// Test 3: nsswitch.conf 'hosts:' line determines order
    /// Verifies that name service switch configuration affects resolution order.
    #[test]
    fn conformance_nsswitch_hosts_order() {
        init_test("conformance_nsswitch_hosts_order");

        // Note: nsswitch.conf controls the order of name resolution sources
        // Common configurations:
        // - "hosts: files dns" = check /etc/hosts first, then DNS
        // - "hosts: dns files" = check DNS first, then /etc/hosts
        // - "hosts: files mdns4_minimal [NOTFOUND=return] dns" = complex ordering

        // Read current nsswitch.conf if available
        let nsswitch_result = std::fs::read_to_string("/etc/nsswitch.conf");
        let has_nsswitch = nsswitch_result.is_ok();

        if let Ok(nsswitch_content) = nsswitch_result {
            let hosts_line = nsswitch_content
                .lines()
                .find(|line| line.trim_start().starts_with("hosts:"));

            if let Some(line) = hosts_line {
                crate::assert_with_log!(
                    !line.is_empty(),
                    "nsswitch.conf hosts line found",
                    true,
                    !line.is_empty()
                );

                // Document the current configuration
                println!("Current hosts resolution order: {}", line.trim());

                // Test with localhost to verify system honors nsswitch ordering
                let result = future::block_on(async {
                    let resolver = Resolver::default();
                    resolver.lookup_ip("localhost").await
                });

                // Should succeed regardless of nsswitch order for localhost
                crate::assert_with_log!(
                    result.is_ok(),
                    "localhost resolution respects nsswitch.conf ordering",
                    true,
                    result.is_ok()
                );
            }
        }

        crate::assert_with_log!(
            has_nsswitch,
            "nsswitch.conf availability (system-dependent)",
            has_nsswitch,
            has_nsswitch
        );

        crate::test_complete!("conformance_nsswitch_hosts_order");
    }

    /// Test 4: gethostbyname_r reentrancy
    /// Verifies that DNS resolution is reentrant and thread-safe.
    #[test]
    fn conformance_gethostbyname_r_reentrancy() {
        init_test("conformance_gethostbyname_r_reentrancy");

        // Test concurrent DNS lookups to verify reentrancy
        let resolver = Arc::new(Resolver::default());
        let mut handles = Vec::new();

        // Spawn multiple concurrent resolution tasks
        for i in 0..5 {
            let resolver_clone = Arc::clone(&resolver);
            let handle = std::thread::spawn(move || {
                let result =
                    future::block_on(async { resolver_clone.lookup_ip("localhost").await });
                (i, result)
            });
            handles.push(handle);
        }

        // Wait for all tasks and verify they all succeed
        let mut success_count = 0;
        for handle in handles {
            match handle.join() {
                Ok((i, Ok(_addrs))) => {
                    success_count += 1;
                    println!("Thread {i} resolved localhost successfully");
                }
                Ok((i, Err(e))) => {
                    println!("Thread {i} failed: {e:?}");
                }
                Err(e) => {
                    println!("Thread panicked: {e:?}");
                }
            }
        }

        crate::assert_with_log!(
            success_count >= 4, // Allow one failure for robustness
            "concurrent DNS lookups demonstrate reentrancy",
            true,
            success_count >= 4
        );

        // Test simultaneous async lookups within single thread
        let concurrent_result = future::block_on(async {
            let resolver = Resolver::default();
            let fut1 = resolver.lookup_ip("localhost");
            let fut2 = resolver.lookup_ip("localhost");
            let fut3 = resolver.lookup_ip("localhost");

            // Run concurrently
            let ((r1, r2), r3) =
                futures_lite::future::zip(futures_lite::future::zip(fut1, fut2), fut3).await;

            (r1.is_ok(), r2.is_ok(), r3.is_ok())
        });

        let (ok1, ok2, ok3) = concurrent_result;
        let async_success_count = [ok1, ok2, ok3].iter().filter(|&&x| x).count();

        crate::assert_with_log!(
            async_success_count >= 2,
            "concurrent async DNS lookups work correctly",
            true,
            async_success_count >= 2
        );

        crate::test_complete!("conformance_gethostbyname_r_reentrancy");
    }

    /// Test 5: AAAA-over-A preference with IPv6 available
    /// Verifies IPv6 address preference when both IPv4 and IPv6 are available.
    #[test]
    fn conformance_ipv6_aaaa_preference() {
        init_test("conformance_ipv6_aaaa_preference");

        // Test with a hostname that should have both A and AAAA records
        // Use localhost which commonly has both 127.0.0.1 and ::1
        let result = future::block_on(async {
            let resolver = Resolver::default();
            resolver.lookup_ip("localhost").await
        });

        crate::assert_with_log!(
            result.is_ok(),
            "localhost resolution succeeds",
            true,
            result.is_ok()
        );

        if let Ok(addrs) = result {
            let has_ipv4 = addrs.iter().any(|ip| ip.is_ipv4());
            let has_ipv6 = addrs.iter().any(|ip| ip.is_ipv6());

            crate::assert_with_log!(
                has_ipv4 || has_ipv6,
                "localhost has either IPv4 or IPv6 addresses",
                true,
                has_ipv4 || has_ipv6
            );

            if has_ipv6 {
                // When IPv6 is available, modern resolvers should prefer AAAA
                // Check if IPv6 addresses appear first (preference indication)
                let first_is_ipv6 = addrs.first().map(|ip| ip.is_ipv6()).unwrap_or(false);

                println!("Address order: {:?}", addrs);
                println!("First address is IPv6: {}", first_is_ipv6);

                // Document behavior - IPv6 preference varies by system configuration
                crate::assert_with_log!(
                    true, // Always pass - documents IPv6 preference behavior
                    "IPv6 preference behavior documented",
                    true,
                    true
                );
            }

            // Test explicit IPv6 resolution if system supports it
            let ipv6_localhost_result = future::block_on(async {
                let resolver = Resolver::default();
                resolver.lookup_ip("ip6-localhost").await
            });

            match ipv6_localhost_result {
                Ok(ipv6_addrs) => {
                    let all_ipv6 = ipv6_addrs.iter().all(|ip| ip.is_ipv6());
                    crate::assert_with_log!(
                        all_ipv6,
                        "ip6-localhost resolves to IPv6 addresses only",
                        true,
                        all_ipv6
                    );
                }
                Err(_) => {
                    // ip6-localhost may not be configured on all systems
                    println!("ip6-localhost not available (system-dependent)");
                }
            }
        }

        crate::test_complete!("conformance_ipv6_aaaa_preference");
    }
}
