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
#[path = "transport_select_inline_tests.rs"]
mod tests;
