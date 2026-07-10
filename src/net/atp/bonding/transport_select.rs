//! Multi-donor bonding transport selection foundations (`z01bbr.4.3` +
//! `z01bbr.4.4`).
//!
//! Pure, unit-testable logic for two Phase-D concerns. Nothing here wires into
//! `bond-pull` — a later integration step consumes these functions.
//!
//! * `z01bbr.4.3` — **local Tailscale detection**. [`detect_local_tailnet`]
//!   probes `tailscale status --json` (falling back to `tailscale ip -4`) and
//!   returns the local node's tailnet identity, or `None` when tailscale is not
//!   installed / the host is not on a tailnet. The command-output parsing is
//!   factored into pure `&str -> …` functions ([`parse_tailscale_status_ipv4`],
//!   [`parse_tailscale_ip_line`], [`is_cgnat_ipv4`]) so it is testable without
//!   tailscale installed.
//! * `z01bbr.4.4` — **per-donor path selection**. [`select_donor_path`] takes a
//!   receiver's advertised direct/tailnet endpoints, a [`TransportPreference`],
//!   and whether the donor is on the tailnet, then picks a [`BondTransport`]
//!   family and dial address. The ranking intent mirrors
//!   [`crate::atp::path::PathKind::preference_rank`]: Tailscale > direct > relay
//!   > mailbox.

use std::net::{Ipv4Addr, SocketAddr};
use std::process::Command;

use super::BondTransport;

/// Local Tailscale identity discovered from the `tailscale` CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailnetIdentity {
    /// The node's CGNAT (`100.64.0.0/10`) IPv4 tailnet address.
    pub ipv4: Ipv4Addr,
    /// The node's MagicDNS name, when Tailscale reports one (trailing dot
    /// stripped). `None` when running through the `tailscale ip -4` fallback,
    /// which does not carry a DNS name.
    pub magic_dns: Option<String>,
}

/// Whether `ip` is in the Tailscale CGNAT range `100.64.0.0/10`.
///
/// RFC 6598 shared address space spans `100.64.0.0`–`100.127.255.255`: the first
/// octet is `100` and the second octet is in `64..=127`.
#[must_use]
pub fn is_cgnat_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    a == 100 && (64..=127).contains(&b)
}

/// Normalize a MagicDNS name: trim surrounding whitespace and the trailing dot
/// that `tailscale status --json` reports on fully-qualified names.
fn normalize_magic_dns(name: &str) -> String {
    name.trim().trim_end_matches('.').to_string()
}

/// Parse `tailscale status --json` stdout for the local node's CGNAT IPv4 and
/// MagicDNS name.
///
/// Returns the first `Self.TailscaleIPs` entry that parses as a CGNAT IPv4
/// (`100.64.0.0/10`) together with `Self.DNSName`, when present and non-empty.
/// Returns `None` when the JSON is malformed or carries no usable tailnet IPv4.
#[must_use]
pub fn parse_tailscale_status_ipv4(json: &str) -> Option<(Ipv4Addr, Option<String>)> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let self_node = value.get("Self")?;
    let ipv4 = self_node
        .get("TailscaleIPs")?
        .as_array()?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .filter_map(|entry| entry.parse::<Ipv4Addr>().ok())
        .find(|ip| is_cgnat_ipv4(*ip))?;
    let magic_dns = self_node
        .get("DNSName")
        .and_then(serde_json::Value::as_str)
        .map(normalize_magic_dns)
        .filter(|name| !name.is_empty());
    Some((ipv4, magic_dns))
}

/// Parse `tailscale ip -4` stdout: the first line that is a CGNAT IPv4.
///
/// Blank lines and any line that is not a `100.64.0.0/10` IPv4 are skipped, so a
/// stray non-tailnet address never masquerades as the tailnet identity.
#[must_use]
pub fn parse_tailscale_ip_line(stdout: &str) -> Option<Ipv4Addr> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| line.parse::<Ipv4Addr>().ok())
        .find(|ip| is_cgnat_ipv4(*ip))
}

/// Detect the local node's Tailscale identity, if this host is on a tailnet.
///
/// Runs `tailscale status --json` first; on any failure (command missing,
/// non-zero exit, unparseable output, no tailnet IPv4) it falls back to
/// `tailscale ip -4`. Returns `None` when tailscale is not installed or the host
/// is not on a tailnet. Shells out via raw [`std::process::Command`], matching
/// the ATP CLI convention for ssh/tailscale probes.
#[must_use]
pub fn detect_local_tailnet() -> Option<TailnetIdentity> {
    detect_via_status_json().or_else(detect_via_ip_flag)
}

fn detect_via_status_json() -> Option<TailnetIdentity> {
    let output = Command::new("tailscale")
        .arg("status")
        .arg("--json")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let (ipv4, magic_dns) = parse_tailscale_status_ipv4(&stdout)?;
    Some(TailnetIdentity { ipv4, magic_dns })
}

fn detect_via_ip_flag() -> Option<TailnetIdentity> {
    let output = Command::new("tailscale")
        .arg("ip")
        .arg("-4")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let ipv4 = parse_tailscale_ip_line(&stdout)?;
    Some(TailnetIdentity {
        ipv4,
        magic_dns: None,
    })
}

/// Receiver-advertised dial endpoints for a bonded transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiverEndpoints {
    /// Direct (public/LAN) UDP socket address, if the receiver advertised one.
    pub direct: Option<SocketAddr>,
    /// Tailnet (Tailscale) socket address, if the receiver advertised one.
    pub tailnet: Option<SocketAddr>,
}

/// Operator transport preference; mirrors the future `bond-pull --transport`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportPreference {
    /// Pick the most-preferred usable transport automatically.
    Auto,
    /// Prefer the Tailscale path; fall back only when it is unusable.
    Tailscale,
    /// Prefer a direct IP path.
    Direct,
    /// Bootstrap over an SSH tunnel.
    Ssh,
}

/// Chosen bonded transport family + dial address for one donor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DonorPathChoice {
    /// Negotiated transport family.
    pub transport: BondTransport,
    /// Socket address this donor should dial.
    pub dial: SocketAddr,
}

/// Select a bonded transport + dial address for one donor.
///
/// Ranking intent (Tailscale > direct > relay/SSH-bootstrap), applied per
/// preference:
///
/// * `Ssh` — always an SSH-tunnel bootstrap, dialing the direct endpoint when
///   present, otherwise the tailnet endpoint.
/// * `Tailscale` / `Auto` — use [`BondTransport::Tailscale`] dialing the tailnet
///   endpoint **iff** the receiver advertised one and the donor is on the
///   tailnet (i.e. both ends share the tailnet); otherwise fall back to a direct
///   endpoint.
/// * `Direct` — use [`BondTransport::DirectIp`] dialing the direct endpoint,
///   ignoring any tailnet endpoint.
///
/// Whenever the preferred family is unavailable, a direct endpoint is the next
/// choice, and a shared-tailnet endpoint is the last resort. Returns `None` only
/// when no usable endpoint exists.
#[must_use]
pub fn select_donor_path(
    pref: TransportPreference,
    endpoints: &ReceiverEndpoints,
    donor_on_tailnet: bool,
) -> Option<DonorPathChoice> {
    // Explicit SSH bootstrap tunnels over the best reachable endpoint.
    if matches!(pref, TransportPreference::Ssh) {
        let dial = endpoints.direct.or(endpoints.tailnet)?;
        return Some(DonorPathChoice {
            transport: BondTransport::Ssh,
            dial,
        });
    }

    // Tailscale is chosen explicitly, or automatically when both ends are on the
    // tailnet: the donor is on the tailnet and the receiver advertised a tailnet
    // endpoint.
    let want_tailscale = matches!(
        pref,
        TransportPreference::Tailscale | TransportPreference::Auto
    );
    if want_tailscale
        && donor_on_tailnet
        && let Some(dial) = endpoints.tailnet
    {
        return Some(DonorPathChoice {
            transport: BondTransport::Tailscale,
            dial,
        });
    }

    // Direct IP is the preferred fallback whenever a direct endpoint exists.
    if let Some(dial) = endpoints.direct {
        return Some(DonorPathChoice {
            transport: BondTransport::DirectIp,
            dial,
        });
    }

    // Last resort: a tailnet endpoint with no direct path, usable only when the
    // donor shares the tailnet.
    if donor_on_tailnet && let Some(dial) = endpoints.tailnet {
        return Some(DonorPathChoice {
            transport: BondTransport::Tailscale,
            dial,
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn direct_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 4711)
    }

    fn tailnet_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 101, 102, 103)), 4711)
    }

    // --- z01bbr.4.3: CGNAT classification -----------------------------------

    #[test]
    fn is_cgnat_ipv4_accepts_the_full_100_64_0_0_slash_10_range() {
        assert!(is_cgnat_ipv4(Ipv4Addr::new(100, 64, 0, 0)));
        assert!(is_cgnat_ipv4(Ipv4Addr::new(100, 127, 255, 255)));
        assert!(is_cgnat_ipv4(Ipv4Addr::new(100, 96, 12, 34)));
    }

    #[test]
    fn is_cgnat_ipv4_rejects_addresses_just_outside_the_boundaries() {
        // One below the low boundary (100.63.255.255) and one above the high
        // boundary (100.128.0.0).
        assert!(!is_cgnat_ipv4(Ipv4Addr::new(100, 63, 255, 255)));
        assert!(!is_cgnat_ipv4(Ipv4Addr::new(100, 128, 0, 0)));
        // Ordinary public / private addresses are rejected.
        assert!(!is_cgnat_ipv4(Ipv4Addr::new(203, 0, 113, 7)));
        assert!(!is_cgnat_ipv4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!is_cgnat_ipv4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_cgnat_ipv4(Ipv4Addr::new(100, 200, 0, 1)));
    }

    // --- z01bbr.4.3: status --json parsing ----------------------------------

    #[test]
    fn parse_tailscale_status_ipv4_extracts_self_cgnat_ip_and_magic_dns() {
        // Realistic (trimmed) `tailscale status --json` snippet.
        let json = r#"{
            "Version": "1.62.0",
            "BackendState": "Running",
            "Self": {
                "ID": "n123",
                "HostName": "workstation",
                "DNSName": "workstation.tail9f00.ts.net.",
                "TailscaleIPs": ["100.101.102.103", "fd7a:115c:a1e0::1234"],
                "Online": true
            },
            "Peer": {}
        }"#;
        let (ipv4, magic_dns) = parse_tailscale_status_ipv4(json).expect("self cgnat ip present");
        assert_eq!(ipv4, Ipv4Addr::new(100, 101, 102, 103));
        // Trailing dot stripped.
        assert_eq!(magic_dns.as_deref(), Some("workstation.tail9f00.ts.net"));
    }

    #[test]
    fn parse_tailscale_status_ipv4_skips_non_cgnat_ipv4_and_ipv6() {
        // First IPv4 is NOT in CGNAT; the CGNAT one appears later in the list.
        let json = r#"{
            "Self": {
                "DNSName": "host.example.ts.net.",
                "TailscaleIPs": ["192.0.2.9", "fd7a:115c::1", "100.64.0.5"]
            }
        }"#;
        let (ipv4, magic_dns) = parse_tailscale_status_ipv4(json).expect("later cgnat ip found");
        assert_eq!(ipv4, Ipv4Addr::new(100, 64, 0, 5));
        assert_eq!(magic_dns.as_deref(), Some("host.example.ts.net"));
    }

    #[test]
    fn parse_tailscale_status_ipv4_returns_none_without_a_cgnat_address() {
        let json = r#"{ "Self": { "TailscaleIPs": ["192.0.2.9", "fd7a::1"] } }"#;
        assert!(parse_tailscale_status_ipv4(json).is_none());
    }

    #[test]
    fn parse_tailscale_status_ipv4_returns_none_on_malformed_or_empty_json() {
        assert!(parse_tailscale_status_ipv4("not json at all").is_none());
        assert!(parse_tailscale_status_ipv4("").is_none());
        assert!(parse_tailscale_status_ipv4("{}").is_none());
        assert!(parse_tailscale_status_ipv4(r#"{ "Self": {} }"#).is_none());
    }

    #[test]
    fn parse_tailscale_status_ipv4_omits_empty_dns_name() {
        let json = r#"{
            "Self": { "DNSName": "", "TailscaleIPs": ["100.100.100.100"] }
        }"#;
        let (ipv4, magic_dns) = parse_tailscale_status_ipv4(json).expect("cgnat ip");
        assert_eq!(ipv4, Ipv4Addr::new(100, 100, 100, 100));
        assert_eq!(magic_dns, None);
    }

    // --- z01bbr.4.3: `tailscale ip -4` fallback parsing ----------------------

    #[test]
    fn parse_tailscale_ip_line_takes_the_first_cgnat_line() {
        let stdout = "100.115.92.1\nfd7a:115c:a1e0::1\n";
        assert_eq!(
            parse_tailscale_ip_line(stdout),
            Some(Ipv4Addr::new(100, 115, 92, 1))
        );
    }

    #[test]
    fn parse_tailscale_ip_line_skips_blanks_and_non_cgnat_lines() {
        let stdout = "\n   \n192.0.2.4\n100.72.0.9\n";
        assert_eq!(
            parse_tailscale_ip_line(stdout),
            Some(Ipv4Addr::new(100, 72, 0, 9))
        );
    }

    #[test]
    fn parse_tailscale_ip_line_returns_none_when_no_cgnat_line() {
        assert!(parse_tailscale_ip_line("").is_none());
        assert!(parse_tailscale_ip_line("not an ip\n").is_none());
        assert!(parse_tailscale_ip_line("192.0.2.4\n").is_none());
    }

    // --- z01bbr.4.4: per-donor path selection decision matrix ---------------

    #[test]
    fn select_auto_both_on_tailnet_picks_tailscale() {
        let endpoints = ReceiverEndpoints {
            direct: Some(direct_addr()),
            tailnet: Some(tailnet_addr()),
        };
        let choice =
            select_donor_path(TransportPreference::Auto, &endpoints, true).expect("usable path");
        assert_eq!(choice.transport, BondTransport::Tailscale);
        assert_eq!(choice.dial, tailnet_addr());
    }

    #[test]
    fn select_auto_donor_not_on_tailnet_picks_direct() {
        let endpoints = ReceiverEndpoints {
            direct: Some(direct_addr()),
            tailnet: Some(tailnet_addr()),
        };
        let choice =
            select_donor_path(TransportPreference::Auto, &endpoints, false).expect("usable path");
        assert_eq!(choice.transport, BondTransport::DirectIp);
        assert_eq!(choice.dial, direct_addr());
    }

    #[test]
    fn select_direct_pref_picks_direct_even_when_tailnet_available() {
        let endpoints = ReceiverEndpoints {
            direct: Some(direct_addr()),
            tailnet: Some(tailnet_addr()),
        };
        let choice =
            select_donor_path(TransportPreference::Direct, &endpoints, true).expect("usable path");
        assert_eq!(choice.transport, BondTransport::DirectIp);
        assert_eq!(choice.dial, direct_addr());
    }

    #[test]
    fn select_tailscale_pref_falls_back_to_direct_when_donor_not_on_tailnet() {
        let endpoints = ReceiverEndpoints {
            direct: Some(direct_addr()),
            tailnet: Some(tailnet_addr()),
        };
        let choice = select_donor_path(TransportPreference::Tailscale, &endpoints, false)
            .expect("usable path");
        assert_eq!(choice.transport, BondTransport::DirectIp);
        assert_eq!(choice.dial, direct_addr());
    }

    #[test]
    fn select_tailscale_pref_uses_tailscale_when_both_on_tailnet() {
        let endpoints = ReceiverEndpoints {
            direct: Some(direct_addr()),
            tailnet: Some(tailnet_addr()),
        };
        let choice = select_donor_path(TransportPreference::Tailscale, &endpoints, true)
            .expect("usable path");
        assert_eq!(choice.transport, BondTransport::Tailscale);
        assert_eq!(choice.dial, tailnet_addr());
    }

    #[test]
    fn select_ssh_pref_picks_ssh_dialing_direct() {
        let endpoints = ReceiverEndpoints {
            direct: Some(direct_addr()),
            tailnet: Some(tailnet_addr()),
        };
        let choice =
            select_donor_path(TransportPreference::Ssh, &endpoints, true).expect("usable path");
        assert_eq!(choice.transport, BondTransport::Ssh);
        assert_eq!(choice.dial, direct_addr());
    }

    #[test]
    fn select_ssh_pref_without_direct_tunnels_over_tailnet() {
        let endpoints = ReceiverEndpoints {
            direct: None,
            tailnet: Some(tailnet_addr()),
        };
        let choice =
            select_donor_path(TransportPreference::Ssh, &endpoints, false).expect("usable path");
        assert_eq!(choice.transport, BondTransport::Ssh);
        assert_eq!(choice.dial, tailnet_addr());
    }

    #[test]
    fn select_returns_none_when_no_endpoint_exists() {
        let endpoints = ReceiverEndpoints {
            direct: None,
            tailnet: None,
        };
        assert!(select_donor_path(TransportPreference::Auto, &endpoints, true).is_none());
        assert!(select_donor_path(TransportPreference::Direct, &endpoints, true).is_none());
        assert!(select_donor_path(TransportPreference::Tailscale, &endpoints, true).is_none());
        assert!(select_donor_path(TransportPreference::Ssh, &endpoints, true).is_none());
    }

    #[test]
    fn select_direct_only_endpoint_ignores_tailnet_preference() {
        let endpoints = ReceiverEndpoints {
            direct: Some(direct_addr()),
            tailnet: None,
        };
        // Even asking for Tailscale, with no tailnet endpoint we get direct.
        let choice = select_donor_path(TransportPreference::Tailscale, &endpoints, true)
            .expect("usable path");
        assert_eq!(choice.transport, BondTransport::DirectIp);
        assert_eq!(choice.dial, direct_addr());
    }

    #[test]
    fn select_tailnet_only_endpoint_is_last_resort_when_donor_shares_tailnet() {
        let endpoints = ReceiverEndpoints {
            direct: None,
            tailnet: Some(tailnet_addr()),
        };
        // Direct pref but only a tailnet endpoint: still usable via the shared
        // tailnet, so we return it rather than None.
        let choice =
            select_donor_path(TransportPreference::Direct, &endpoints, true).expect("usable path");
        assert_eq!(choice.transport, BondTransport::Tailscale);
        assert_eq!(choice.dial, tailnet_addr());
        // But if the donor is not on the tailnet, that endpoint is unusable.
        assert!(select_donor_path(TransportPreference::Direct, &endpoints, false).is_none());
    }
}
