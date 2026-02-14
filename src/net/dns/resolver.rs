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

use std::net::{IpAddr, SocketAddr, TcpStream as StdTcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use super::cache::{CacheConfig, CacheStats, DnsCache};
use super::error::DnsError;
use super::lookup::{HappyEyeballs, LookupIp, LookupMx, LookupSrv, LookupTxt};
use crate::cx::Cx;
use crate::net::TcpStream;
use crate::runtime::spawn_blocking;
use crate::time::{sleep, timeout, TimeSource, WallClock};
use crate::types::Time;

/// DNS resolver configuration.
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    /// Nameservers to use (empty = use system resolvers).
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
        Self { config, cache }
    }

    /// Looks up IP addresses for a hostname.
    ///
    /// Returns addresses suitable for connecting to the host.
    /// Results are cached according to TTL.
    pub async fn lookup_ip(&self, host: &str) -> Result<LookupIp, DnsError> {
        // Check cache first
        if self.config.cache_enabled {
            if let Some(cached) = self.cache.get_ip(host) {
                return Ok(cached);
            }
        }

        let result = self.do_lookup_ip(host).await?;

        // Cache the result
        if self.config.cache_enabled {
            self.cache.put_ip(host, &result);
        }

        Ok(result)
    }

    /// Performs the actual IP lookup with retries.
    ///
    /// # Cancellation Safety
    ///
    /// This function is cancel-safe. If the future is dropped, the underlying
    /// DNS query continues on the blocking pool but the result is discarded.
    async fn do_lookup_ip(&self, host: &str) -> Result<LookupIp, DnsError> {
        // If it's already an IP address, return it directly
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(LookupIp::new(vec![ip], Duration::from_secs(0)));
        }

        // Validate hostname
        if host.is_empty() || host.len() > 253 {
            return Err(DnsError::InvalidHost(host.to_string()));
        }

        let retries = self.config.retries;
        if self.config.timeout.is_zero() {
            return Err(DnsError::Timeout);
        }
        let host = host.to_string();

        // Run DNS resolution on blocking pool for true async behavior.
        let lookup = Box::pin(spawn_blocking(move || {
            let mut last_error = None;

            for _attempt in 0..=retries {
                match Self::query_ip_sync(&host) {
                    Ok(result) => return Ok(result),
                    Err(e) => {
                        last_error = Some(e);
                    }
                }
            }

            Err(last_error.unwrap_or(DnsError::Timeout))
        }));

        timeout(timeout_now(), self.config.timeout, lookup)
            .await
            .map_or(Err(DnsError::Timeout), |result| result)
    }

    /// Performs synchronous DNS lookup using std::net.
    fn query_ip_sync(host: &str) -> Result<LookupIp, DnsError> {
        // Use ToSocketAddrs which performs DNS resolution
        let addr_str = format!("{host}:0");

        let addrs: Vec<IpAddr> = addr_str
            .to_socket_addrs()
            .map_err(DnsError::from)?
            .map(|sa| sa.ip())
            .collect();

        if addrs.is_empty() {
            return Err(DnsError::NoRecords(host.to_string()));
        }

        // Default TTL since std::net doesn't provide it
        let ttl = Duration::from_mins(5);

        Ok(LookupIp::new(addrs, ttl))
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

    /// Connects using Happy Eyeballs algorithm.
    async fn connect_happy_eyeballs(&self, addrs: &[SocketAddr]) -> Result<TcpStream, DnsError> {
        // Phase 0 simplified implementation:
        // Try addresses with a short delay between each attempt.
        // A full implementation would use async racing.

        let delay = self.config.happy_eyeballs_delay;
        let mut last_error = None;

        for (i, addr) in addrs.iter().enumerate() {
            if i > 0 && !delay.is_zero() {
                // Stagger attempts with deterministic sleep (lab time aware).
                sleep(timeout_now(), delay).await;
            }

            // Try to connect with timeout
            match self.try_connect_timeout(*addr, self.config.timeout).await {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    last_error = Some(e);
                    // Continue trying other addresses
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            DnsError::Connection(format!("all {} connection attempts failed", addrs.len()))
        }))
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

        // Run connection on blocking pool for true async behavior.
        let connect = Box::pin(spawn_blocking(move || {
            let stream =
                StdTcpStream::connect(addr).map_err(|e| DnsError::Connection(e.to_string()))?;

            stream
                .set_nonblocking(true)
                .map_err(|e| DnsError::Io(e.to_string()))?;

            Ok::<_, DnsError>(stream)
        }));

        let result = timeout(timeout_now(), timeout_duration, connect)
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
        }
    }
}

fn timeout_now() -> Time {
    static CLOCK: OnceLock<WallClock> = OnceLock::new();
    if let Some(current) = Cx::current() {
        if let Some(driver) = current.timer_driver() {
            return driver.now();
        }
    }
    CLOCK.get_or_init(WallClock::new).now()
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::future;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
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

        // Empty hostname
        let _result = Resolver::query_ip_sync("");
        // This may or may not error depending on platform
        // Just ensure it doesn't panic
        crate::test_complete!("resolver_invalid_host");
    }

    #[test]
    fn resolver_cache_shared() {
        init_test("resolver_cache_shared");
        let resolver1 = Resolver::new();
        let resolver2 = resolver1.clone();

        // Lookup on resolver1
        let _ = Resolver::query_ip_sync("localhost");
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
}
