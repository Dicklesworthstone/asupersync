//! Real public-resolver DNS integration test — no fake nameserver.
//!
//! Bead: br-asupersync-3t9amh
//!
//! Run with:
//!     rch exec -- env REAL_DNS_TESTS=true CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_dns_real_upstream cargo test --test dns_real_upstream -- --nocapture
//!
//! Optional environment:
//!     REAL_DNS_NAMESERVER=1.1.1.1
//!
//! Production safety guard blocks `NODE_ENV=production`.

#![cfg(test)]
#![allow(clippy::pedantic, clippy::nursery, clippy::print_stderr)]

use asupersync::net::dns::{DnsError, Resolver, ResolverConfig};
use asupersync::test_utils::run_test_with_cx;

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct RealDnsConfig {
    nameserver: SocketAddr,
    enabled: bool,
    reason: Option<String>,
}

impl RealDnsConfig {
    fn from_env() -> Self {
        let raw_nameserver =
            std::env::var("REAL_DNS_NAMESERVER").unwrap_or_else(|_| "1.1.1.1".to_string());
        let enabled = std::env::var("REAL_DNS_TESTS").unwrap_or_default() == "true";
        let node_env = std::env::var("NODE_ENV").unwrap_or_default();

        let parsed = parse_nameserver(&raw_nameserver);
        let reason = if !enabled {
            Some("REAL_DNS_TESTS not set to 'true' — running unit-only".to_string())
        } else if node_env == "production" {
            Some("BLOCKED: NODE_ENV=production".to_string())
        } else if let Err(err) = &parsed {
            Some(err.clone())
        } else {
            None
        };

        Self {
            nameserver: parsed.unwrap_or_else(|_| SocketAddr::from(([1, 1, 1, 1], 53))),
            enabled: enabled && reason.is_none(),
            reason,
        }
    }
}

fn parse_nameserver(raw: &str) -> Result<SocketAddr, String> {
    if let Ok(addr) = raw.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(format!(
        "BLOCKED: REAL_DNS_NAMESERVER must be an IP or socket address: {raw}"
    ))
}

struct DnsTestLogger {
    suite: &'static str,
    test: &'static str,
    start: Instant,
    phase_count: AtomicU32,
}

impl DnsTestLogger {
    fn new(suite: &'static str, test: &'static str) -> Self {
        let me = Self {
            suite,
            test,
            start: Instant::now(),
            phase_count: AtomicU32::new(0),
        };
        me.line("test_start", &[]);
        me
    }

    fn line(&self, event: &str, fields: &[(&str, String)]) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let mut buf = format!(
            r#"{{"ts":{ts},"suite":"{}","test":"{}","event":"{event}""#,
            self.suite, self.test
        );
        for (key, value) in fields {
            let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
            buf.push_str(&format!(r#","{key}":"{escaped}""#));
        }
        buf.push('}');
        eprintln!("{buf}");
    }

    fn phase(&self, name: &str) {
        let phase_num = self.phase_count.fetch_add(1, Ordering::Relaxed);
        self.line(
            "phase",
            &[
                ("phase", name.to_string()),
                ("phase_num", phase_num.to_string()),
                ("elapsed_ms", self.start.elapsed().as_millis().to_string()),
            ],
        );
    }

    fn end(&self, result: &str) {
        self.line(
            "test_end",
            &[
                ("result", result.to_string()),
                ("duration_ms", self.start.elapsed().as_millis().to_string()),
            ],
        );
    }
}

fn skip_if_disabled(cfg: &RealDnsConfig, test_name: &str) -> bool {
    if !cfg.enabled {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let reason = cfg.reason.as_deref().unwrap_or("disabled");
        eprintln!(
            r#"{{"ts":{ts},"event":"test_skipped","test":"{test_name}","reason":"{reason}"}}"#
        );
        return true;
    }
    false
}

#[test]
fn dns_real_upstream_public_resolver_roundtrip() {
    let cfg = RealDnsConfig::from_env();
    if skip_if_disabled(&cfg, "dns_real_upstream_public_resolver_roundtrip") {
        return;
    }

    let log = DnsTestLogger::new("dns_real", "dns_real_upstream_public_resolver_roundtrip");
    let resolver = Resolver::with_config(ResolverConfig {
        nameservers: vec![cfg.nameserver],
        cache_enabled: false,
        timeout: Duration::from_secs(5),
        retries: 1,
        ..ResolverConfig::default()
    });

    run_test_with_cx(|_cx| async move {
        log.phase("lookup_ip_example_com");
        let ip_lookup = resolver
            .lookup_ip("example.com")
            .await
            .expect("example.com IP lookup should succeed");
        let total = ip_lookup.len();
        let ipv4 = ip_lookup.ipv4_addrs().count();
        let ipv6 = ip_lookup.ipv6_addrs().count();
        log.line(
            "lookup_ip",
            &[
                ("host", "example.com".to_string()),
                ("nameserver", cfg.nameserver.to_string()),
                ("records", total.to_string()),
                ("ipv4", ipv4.to_string()),
                ("ipv6", ipv6.to_string()),
                ("ttl_secs", ip_lookup.ttl().as_secs().to_string()),
            ],
        );
        assert!(total > 0, "example.com should return at least one address");

        log.phase("lookup_mx_gmail_com");
        let mx_lookup = resolver
            .lookup_mx("gmail.com")
            .await
            .expect("gmail.com MX lookup should succeed");
        let mx_records: Vec<_> = mx_lookup.records().collect();
        log.line(
            "lookup_mx",
            &[
                ("domain", "gmail.com".to_string()),
                ("records", mx_records.len().to_string()),
            ],
        );
        assert!(!mx_records.is_empty(), "gmail.com should expose MX records");
        assert!(
            mx_records.iter().all(|record| !record.exchange.is_empty()),
            "MX exchanges should not be empty"
        );

        log.phase("lookup_txt_google_com");
        let txt_lookup = resolver
            .lookup_txt("google.com")
            .await
            .expect("google.com TXT lookup should succeed");
        let txt_records: Vec<_> = txt_lookup.records().collect();
        log.line(
            "lookup_txt",
            &[
                ("name", "google.com".to_string()),
                ("records", txt_records.len().to_string()),
            ],
        );
        assert!(
            txt_records.iter().any(|record| !record.is_empty()),
            "google.com should expose at least one non-empty TXT record"
        );

        log.phase("lookup_nxdomain");
        let nxdomain = resolver
            .lookup_ip("asupersync-real-upstream-nxdomain.example.com")
            .await;
        match nxdomain {
            Err(DnsError::NoRecords(host)) => {
                log.line("lookup_nxdomain", &[("host", host)]);
            }
            Err(other) => panic!("expected NoRecords for NXDOMAIN probe, got {other}"),
            Ok(lookup) => panic!(
                "expected NXDOMAIN probe to fail, got {} addresses",
                lookup.len()
            ),
        }

        log.end("pass");
    });
}
