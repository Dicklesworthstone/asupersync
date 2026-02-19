//! DNS lookup result types.
//!
//! This module defines the result types returned by DNS queries.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// Result of an IP address lookup.
#[derive(Debug, Clone)]
pub struct LookupIp {
    addresses: Vec<IpAddr>,
    ttl: Duration,
}

impl LookupIp {
    /// Creates a new lookup result.
    #[must_use]
    pub fn new(addresses: Vec<IpAddr>, ttl: Duration) -> Self {
        Self { addresses, ttl }
    }

    /// Returns the resolved addresses.
    #[must_use]
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    /// Returns the TTL (time to live) for the cached result.
    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Returns the first address, if any.
    #[must_use]
    pub fn first(&self) -> Option<IpAddr> {
        self.addresses.first().copied()
    }

    /// Returns true if no addresses were resolved.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// Returns the number of resolved addresses.
    #[must_use]
    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    /// Returns an iterator over the addresses.
    pub fn iter(&self) -> impl Iterator<Item = &IpAddr> {
        self.addresses.iter()
    }

    /// Returns only IPv4 addresses.
    pub fn ipv4_addrs(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.addresses.iter().filter_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            IpAddr::V6(_) => None,
        })
    }

    /// Returns only IPv6 addresses.
    pub fn ipv6_addrs(&self) -> impl Iterator<Item = Ipv6Addr> + '_ {
        self.addresses.iter().filter_map(|ip| match ip {
            IpAddr::V4(_) => None,
            IpAddr::V6(v6) => Some(*v6),
        })
    }
}

impl IntoIterator for LookupIp {
    type Item = IpAddr;
    type IntoIter = std::vec::IntoIter<IpAddr>;

    fn into_iter(self) -> Self::IntoIter {
        self.addresses.into_iter()
    }
}

impl<'a> IntoIterator for &'a LookupIp {
    type Item = &'a IpAddr;
    type IntoIter = std::slice::Iter<'a, IpAddr>;

    fn into_iter(self) -> Self::IntoIter {
        self.addresses.iter()
    }
}

/// Happy Eyeballs (RFC 6555) address iterator.
///
/// Interleaves IPv6 and IPv4 addresses for optimal connection racing:
/// IPv6_1, IPv4_1, IPv6_2, IPv4_2, ...
#[derive(Debug, Clone)]
pub struct HappyEyeballs {
    v6: Vec<Ipv6Addr>,
    v4: Vec<Ipv4Addr>,
    v6_idx: usize,
    v4_idx: usize,
    prefer_v6: bool,
}

impl HappyEyeballs {
    /// Creates a new Happy Eyeballs iterator from a lookup result.
    #[must_use]
    pub fn from_lookup(lookup: &LookupIp) -> Self {
        Self {
            v6: lookup.ipv6_addrs().collect(),
            v4: lookup.ipv4_addrs().collect(),
            v6_idx: 0,
            v4_idx: 0,
            prefer_v6: true,
        }
    }

    /// Creates a new Happy Eyeballs iterator from separate address lists.
    #[must_use]
    pub fn new(v6: Vec<Ipv6Addr>, v4: Vec<Ipv4Addr>) -> Self {
        Self {
            v6,
            v4,
            v6_idx: 0,
            v4_idx: 0,
            prefer_v6: true,
        }
    }

    /// Returns true if there are no more addresses.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.v6_idx >= self.v6.len() && self.v4_idx >= self.v4.len()
    }

    /// Returns the total number of remaining addresses.
    #[must_use]
    pub fn remaining(&self) -> usize {
        (self.v6.len() - self.v6_idx) + (self.v4.len() - self.v4_idx)
    }
}

impl Iterator for HappyEyeballs {
    type Item = IpAddr;

    fn next(&mut self) -> Option<Self::Item> {
        // Interleave: try preferred family first, then alternate
        if self.prefer_v6 {
            if self.v6_idx < self.v6.len() {
                let addr = self.v6[self.v6_idx];
                self.v6_idx += 1;
                self.prefer_v6 = false;
                return Some(IpAddr::V6(addr));
            }
            // No more v6, try v4
            if self.v4_idx < self.v4.len() {
                let addr = self.v4[self.v4_idx];
                self.v4_idx += 1;
                return Some(IpAddr::V4(addr));
            }
        } else {
            if self.v4_idx < self.v4.len() {
                let addr = self.v4[self.v4_idx];
                self.v4_idx += 1;
                self.prefer_v6 = true;
                return Some(IpAddr::V4(addr));
            }
            // No more v4, try v6
            if self.v6_idx < self.v6.len() {
                let addr = self.v6[self.v6_idx];
                self.v6_idx += 1;
                return Some(IpAddr::V6(addr));
            }
        }
        None
    }
}

/// MX record lookup result.
#[derive(Debug, Clone)]
pub struct LookupMx {
    records: Vec<MxRecord>,
}

impl LookupMx {
    /// Creates a new MX lookup result.
    #[must_use]
    pub fn new(mut records: Vec<MxRecord>) -> Self {
        // Keep MX records in RFC-priority order so callers can iterate directly.
        records.sort_by(|a, b| {
            a.preference
                .cmp(&b.preference)
                .then_with(|| a.exchange.cmp(&b.exchange))
        });
        Self { records }
    }

    /// Returns the MX records, sorted by preference.
    pub fn records(&self) -> impl Iterator<Item = &MxRecord> {
        self.records.iter()
    }
}

/// An MX (mail exchange) record.
#[derive(Debug, Clone)]
pub struct MxRecord {
    /// Priority/preference value (lower is higher priority).
    pub preference: u16,
    /// Mail server hostname.
    pub exchange: String,
}

/// SRV record lookup result.
#[derive(Debug, Clone)]
pub struct LookupSrv {
    records: Vec<SrvRecord>,
}

impl LookupSrv {
    /// Creates a new SRV lookup result.
    #[must_use]
    pub fn new(records: Vec<SrvRecord>) -> Self {
        Self { records }
    }

    /// Returns the SRV records.
    pub fn records(&self) -> impl Iterator<Item = &SrvRecord> {
        self.records.iter()
    }
}

/// An SRV (service) record.
#[derive(Debug, Clone)]
pub struct SrvRecord {
    /// Priority value (lower is higher priority).
    pub priority: u16,
    /// Weight for load balancing among same-priority records.
    pub weight: u16,
    /// Port number for the service.
    pub port: u16,
    /// Target hostname.
    pub target: String,
}

/// TXT record lookup result.
#[derive(Debug, Clone)]
pub struct LookupTxt {
    records: Vec<String>,
}

impl LookupTxt {
    /// Creates a new TXT lookup result.
    #[must_use]
    pub fn new(records: Vec<String>) -> Self {
        Self { records }
    }

    /// Returns the TXT record strings.
    pub fn records(&self) -> impl Iterator<Item = &str> {
        self.records.iter().map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn happy_eyeballs_interleaves() {
        init_test("happy_eyeballs_interleaves");
        let v6 = vec![
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
        ];
        let v4 = vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()];

        let he = HappyEyeballs::new(v6, v4);
        let addrs: Vec<_> = he.collect();

        // Should interleave: v6, v4, v6, v4
        let len = addrs.len();
        crate::assert_with_log!(len == 4, "len", 4, len);
        crate::assert_with_log!(addrs[0].is_ipv6(), "addr0 v6", true, addrs[0]);
        crate::assert_with_log!(addrs[1].is_ipv4(), "addr1 v4", true, addrs[1]);
        crate::assert_with_log!(addrs[2].is_ipv6(), "addr2 v6", true, addrs[2]);
        crate::assert_with_log!(addrs[3].is_ipv4(), "addr3 v4", true, addrs[3]);
        crate::test_complete!("happy_eyeballs_interleaves");
    }

    #[test]
    fn happy_eyeballs_uneven() {
        init_test("happy_eyeballs_uneven");
        let v6 = vec!["2001:db8::1".parse().unwrap()];
        let v4 = vec![
            "192.0.2.1".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            "192.0.2.3".parse().unwrap(),
        ];

        let he = HappyEyeballs::new(v6, v4);
        let addrs: Vec<_> = he.collect();

        let len = addrs.len();
        crate::assert_with_log!(len == 4, "len", 4, len);
        // v6, v4, v4, v4 (v6 exhausted after first)
        crate::assert_with_log!(addrs[0].is_ipv6(), "addr0 v6", true, addrs[0]);
        crate::assert_with_log!(addrs[1].is_ipv4(), "addr1 v4", true, addrs[1]);
        crate::assert_with_log!(addrs[2].is_ipv4(), "addr2 v4", true, addrs[2]);
        crate::assert_with_log!(addrs[3].is_ipv4(), "addr3 v4", true, addrs[3]);
        crate::test_complete!("happy_eyeballs_uneven");
    }

    #[test]
    fn lookup_ip_accessors() {
        init_test("lookup_ip_accessors");
        let lookup = LookupIp::new(
            vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
            Duration::from_mins(5),
        );

        let len = lookup.len();
        crate::assert_with_log!(len == 2, "len", 2, len);
        let empty = lookup.is_empty();
        crate::assert_with_log!(!empty, "not empty", false, empty);
        let v4_count = lookup.ipv4_addrs().count();
        crate::assert_with_log!(v4_count == 1, "ipv4 count", 1, v4_count);
        let v6_count = lookup.ipv6_addrs().count();
        crate::assert_with_log!(v6_count == 1, "ipv6 count", 1, v6_count);
        crate::test_complete!("lookup_ip_accessors");
    }

    // ========================================================================
    // Pure data-type tests (wave 10 – CyanBarn)
    // ========================================================================

    #[test]
    fn lookup_ip_empty() {
        init_test("lookup_ip_empty");
        let lookup = LookupIp::new(vec![], Duration::from_mins(1));
        assert!(lookup.is_empty());
        assert_eq!(lookup.len(), 0);
        assert!(lookup.first().is_none());
        assert_eq!(lookup.ipv4_addrs().count(), 0);
        assert_eq!(lookup.ipv6_addrs().count(), 0);
        crate::test_complete!("lookup_ip_empty");
    }

    #[test]
    fn lookup_ip_debug_clone() {
        init_test("lookup_ip_debug_clone");
        let lookup = LookupIp::new(vec!["10.0.0.1".parse().unwrap()], Duration::from_secs(30));
        let dbg = format!("{lookup:?}");
        assert!(dbg.contains("LookupIp"), "{dbg}");
        let cloned = lookup;
        assert_eq!(cloned.len(), 1);
        assert_eq!(cloned.ttl(), Duration::from_secs(30));
        crate::test_complete!("lookup_ip_debug_clone");
    }

    #[test]
    fn lookup_ip_first() {
        init_test("lookup_ip_first");
        let lookup = LookupIp::new(
            vec!["1.2.3.4".parse().unwrap(), "5.6.7.8".parse().unwrap()],
            Duration::from_mins(1),
        );
        assert_eq!(lookup.first(), Some("1.2.3.4".parse().unwrap()));
        crate::test_complete!("lookup_ip_first");
    }

    #[test]
    fn lookup_ip_iter() {
        init_test("lookup_ip_iter");
        let lookup = LookupIp::new(
            vec!["1.1.1.1".parse().unwrap(), "2.2.2.2".parse().unwrap()],
            Duration::from_secs(10),
        );
        let count = lookup.iter().count();
        assert_eq!(count, 2);
        crate::test_complete!("lookup_ip_iter");
    }

    #[test]
    fn lookup_ip_into_iter_owned() {
        init_test("lookup_ip_into_iter_owned");
        let lookup = LookupIp::new(vec!["10.0.0.1".parse().unwrap()], Duration::from_secs(5));
        let addrs: Vec<_> = lookup.into_iter().collect();
        assert_eq!(addrs.len(), 1);
        crate::test_complete!("lookup_ip_into_iter_owned");
    }

    #[test]
    fn lookup_ip_into_iter_ref() {
        init_test("lookup_ip_into_iter_ref");
        let lookup = LookupIp::new(vec!["10.0.0.1".parse().unwrap()], Duration::from_secs(5));
        let addrs: Vec<_> = (&lookup).into_iter().collect();
        assert_eq!(addrs.len(), 1);
        crate::test_complete!("lookup_ip_into_iter_ref");
    }

    #[test]
    fn lookup_ip_ipv4_only() {
        init_test("lookup_ip_ipv4_only");
        let lookup = LookupIp::new(
            vec![
                "10.0.0.1".parse().unwrap(),
                "::1".parse().unwrap(),
                "10.0.0.2".parse().unwrap(),
            ],
            Duration::from_mins(1),
        );
        let v4: Vec<_> = lookup.ipv4_addrs().collect();
        assert_eq!(v4.len(), 2);
        assert_eq!(v4[0], "10.0.0.1".parse::<Ipv4Addr>().unwrap());
        crate::test_complete!("lookup_ip_ipv4_only");
    }

    #[test]
    fn lookup_ip_ipv6_only() {
        init_test("lookup_ip_ipv6_only");
        let lookup = LookupIp::new(
            vec!["10.0.0.1".parse().unwrap(), "::1".parse().unwrap()],
            Duration::from_mins(1),
        );
        let v6: Vec<_> = lookup.ipv6_addrs().collect();
        assert_eq!(v6.len(), 1);
        crate::test_complete!("lookup_ip_ipv6_only");
    }

    #[test]
    fn happy_eyeballs_empty() {
        init_test("happy_eyeballs_empty");
        let he = HappyEyeballs::new(vec![], vec![]);
        assert!(he.is_empty());
        assert_eq!(he.remaining(), 0);
        let addrs: Vec<_> = he.collect();
        assert!(addrs.is_empty());
        crate::test_complete!("happy_eyeballs_empty");
    }

    #[test]
    fn happy_eyeballs_from_lookup() {
        init_test("happy_eyeballs_from_lookup");
        let lookup = LookupIp::new(
            vec!["10.0.0.1".parse().unwrap(), "::1".parse().unwrap()],
            Duration::from_mins(1),
        );
        let he = HappyEyeballs::from_lookup(&lookup);
        assert!(!he.is_empty());
        assert_eq!(he.remaining(), 2);
        let addrs: Vec<_> = he.collect();
        assert_eq!(addrs.len(), 2);
        // v6 first due to prefer_v6
        assert!(addrs[0].is_ipv6());
        assert!(addrs[1].is_ipv4());
        crate::test_complete!("happy_eyeballs_from_lookup");
    }

    #[test]
    fn happy_eyeballs_v4_only() {
        init_test("happy_eyeballs_v4_only");
        let he = HappyEyeballs::new(
            vec![],
            vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()],
        );
        let addrs: Vec<_> = he.collect();
        assert_eq!(addrs.len(), 2);
        assert!(addrs.iter().all(std::net::IpAddr::is_ipv4));
        crate::test_complete!("happy_eyeballs_v4_only");
    }

    #[test]
    fn happy_eyeballs_v6_only() {
        init_test("happy_eyeballs_v6_only");
        let he = HappyEyeballs::new(vec!["::1".parse().unwrap(), "::2".parse().unwrap()], vec![]);
        let addrs: Vec<_> = he.collect();
        assert_eq!(addrs.len(), 2);
        assert!(addrs.iter().all(std::net::IpAddr::is_ipv6));
        crate::test_complete!("happy_eyeballs_v6_only");
    }

    #[test]
    fn happy_eyeballs_debug_clone() {
        init_test("happy_eyeballs_debug_clone");
        let he = HappyEyeballs::new(vec!["::1".parse().unwrap()], vec![]);
        let dbg = format!("{he:?}");
        assert!(dbg.contains("HappyEyeballs"), "{dbg}");
        let cloned = he;
        assert_eq!(cloned.remaining(), 1);
        crate::test_complete!("happy_eyeballs_debug_clone");
    }

    #[test]
    fn lookup_srv_debug_clone() {
        init_test("lookup_srv_debug_clone");
        let srv = LookupSrv::new(vec![SrvRecord {
            priority: 10,
            weight: 50,
            port: 443,
            target: "srv.example.com".to_string(),
        }]);
        let dbg = format!("{srv:?}");
        assert!(dbg.contains("LookupSrv"), "{dbg}");
        let cloned = srv;
        assert_eq!(cloned.records().count(), 1);
        crate::test_complete!("lookup_srv_debug_clone");
    }

    #[test]
    fn srv_record_debug_clone() {
        init_test("srv_record_debug_clone");
        let rec = SrvRecord {
            priority: 5,
            weight: 100,
            port: 8080,
            target: "host.example".to_string(),
        };
        let dbg = format!("{rec:?}");
        assert!(dbg.contains("SrvRecord"), "{dbg}");
        let cloned = rec;
        assert_eq!(cloned.priority, 5);
        assert_eq!(cloned.port, 8080);
        crate::test_complete!("srv_record_debug_clone");
    }

    #[test]
    fn mx_record_debug_clone() {
        init_test("mx_record_debug_clone");
        let rec = MxRecord {
            preference: 10,
            exchange: "mail.example.com".to_string(),
        };
        let dbg = format!("{rec:?}");
        assert!(dbg.contains("MxRecord"), "{dbg}");
        let cloned = rec;
        assert_eq!(cloned.preference, 10);
        crate::test_complete!("mx_record_debug_clone");
    }

    #[test]
    fn lookup_txt_debug_clone() {
        init_test("lookup_txt_debug_clone");
        let txt = LookupTxt::new(vec!["v=spf1 include:example.com".to_string()]);
        let dbg = format!("{txt:?}");
        assert!(dbg.contains("LookupTxt"), "{dbg}");
        let cloned = txt;
        let records: Vec<_> = cloned.records().collect();
        assert_eq!(records.len(), 1);
        assert!(records[0].contains("spf1"));
        crate::test_complete!("lookup_txt_debug_clone");
    }

    #[test]
    fn lookup_txt_empty() {
        init_test("lookup_txt_empty");
        let txt = LookupTxt::new(vec![]);
        assert_eq!(txt.records().count(), 0);
        crate::test_complete!("lookup_txt_empty");
    }

    #[test]
    fn lookup_mx_new_sorts_by_preference() {
        init_test("lookup_mx_new_sorts_by_preference");
        let lookup = LookupMx::new(vec![
            MxRecord {
                preference: 20,
                exchange: "mx2.example".to_string(),
            },
            MxRecord {
                preference: 10,
                exchange: "mx1.example".to_string(),
            },
            MxRecord {
                preference: 10,
                exchange: "mx0.example".to_string(),
            },
        ]);
        let records: Vec<_> = lookup.records().collect();

        let first_pref = records[0].preference;
        let second_pref = records[1].preference;
        let third_pref = records[2].preference;
        crate::assert_with_log!(first_pref == 10, "first preference", 10, first_pref);
        crate::assert_with_log!(second_pref == 10, "second preference", 10, second_pref);
        crate::assert_with_log!(third_pref == 20, "third preference", 20, third_pref);

        let first_exchange = records[0].exchange.as_str();
        let second_exchange = records[1].exchange.as_str();
        crate::assert_with_log!(
            first_exchange == "mx0.example",
            "first exchange",
            "mx0.example",
            first_exchange
        );
        crate::assert_with_log!(
            second_exchange == "mx1.example",
            "second exchange",
            "mx1.example",
            second_exchange
        );
        crate::test_complete!("lookup_mx_new_sorts_by_preference");
    }
}
