//! ATP Path Graph lab harness for deterministic NAT/path validation.
//!
//! Implements concrete lab harnesses that execute [`AtpLabScenario`] plans,
//! providing deterministic NAT traversal, path racing, and migration testing.
//!
//! # Quick Start
//!
//! ```ignore
//! use asupersync::lab::atp_path::{AtpPathLabHarness, AtpPathTestConfig};
//! use asupersync::lab::AtpLabScenario;
//!
//! let harness = AtpPathLabHarness::new(AtpPathTestConfig::lan_ipv6());
//! let scenario = AtpLabScenario::new("easy-nat-direct", 0xA7F0_0001)
//!     .with_regime(AtpLabRegime::EasyNat)
//!     .with_regime(AtpLabRegime::Ipv6Direct);
//!
//! let result = harness.execute_scenario(&scenario).await?;
//! assert!(result.path_validation.ipv6_direct_succeeded);
//! ```

pub mod harness;

pub use harness::{
    AtpPathEventKind, AtpPathExecutionResult, AtpPathLabError, AtpPathLabHarness,
    AtpPathTestConfig, AtpPathTraceEvent, AtpPathValidation,
};

use crate::atp::path::PathKind;
use crate::lab::AtpLabRegime;
use crate::net::atp::path::NatProfile;

/// Maps ATP lab regimes to concrete NAT profiles for path testing.
#[must_use]
pub fn regime_to_nat_profile(regime: AtpLabRegime) -> Option<NatProfile> {
    match regime {
        AtpLabRegime::EasyNat => Some(NatProfile::LikelyEasyNat),
        AtpLabRegime::HardNat | AtpLabRegime::SymmetricNat => Some(NatProfile::HardSymmetricNat),
        AtpLabRegime::UdpBlocked => Some(NatProfile::UdpBlocked),
        AtpLabRegime::Ipv6Direct => Some(NatProfile::Ipv6Direct),
        // Other regimes don't directly map to NAT profiles
        _ => None,
    }
}

/// Maps ATP lab regimes to preferred path kinds for path racing.
#[must_use]
pub fn regime_to_path_kind(regime: AtpLabRegime) -> Option<PathKind> {
    match regime {
        AtpLabRegime::LanMulticast => Some(PathKind::LanMulticast),
        AtpLabRegime::EasyNat => Some(PathKind::NatPunchedUdp),
        AtpLabRegime::ExplicitPublicUdp => Some(PathKind::ExplicitPublicUdp),
        AtpLabRegime::Ipv6Direct => Some(PathKind::PublicIpv6),
        AtpLabRegime::HardNat | AtpLabRegime::SymmetricNat => Some(PathKind::NatPunchedUdp),
        AtpLabRegime::UdpBlocked => None, // Forces relay/mailbox fallback
        AtpLabRegime::RelayOnly => Some(PathKind::AtpRelayUdp),
        AtpLabRegime::RelayTcpTls443 => Some(PathKind::AtpRelayTcpTls443),
        AtpLabRegime::TailscalePrivateRoute => Some(PathKind::TailscaleIp),
        AtpLabRegime::MasqueConnectUdpProxy => Some(PathKind::MasqueConnectUdp),
        AtpLabRegime::OfflineMailbox => Some(PathKind::OfflineMailbox),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regime_nat_profile_mapping_covers_network_regimes() {
        // Test all network-related regimes map to appropriate NAT profiles
        assert_eq!(
            regime_to_nat_profile(AtpLabRegime::EasyNat),
            Some(NatProfile::LikelyEasyNat)
        );
        assert_eq!(
            regime_to_nat_profile(AtpLabRegime::Ipv6Direct),
            Some(NatProfile::Ipv6Direct)
        );
        assert_eq!(
            regime_to_nat_profile(AtpLabRegime::HardNat),
            Some(NatProfile::HardSymmetricNat)
        );
        assert_eq!(
            regime_to_nat_profile(AtpLabRegime::UdpBlocked),
            Some(NatProfile::UdpBlocked)
        );
    }

    #[test]
    fn regime_path_kind_mapping_covers_direct_paths() {
        // Test LAN+IPv6 specific mappings
        assert_eq!(
            regime_to_path_kind(AtpLabRegime::LanMulticast),
            Some(PathKind::LanMulticast)
        );
        assert_eq!(
            regime_to_path_kind(AtpLabRegime::EasyNat),
            Some(PathKind::NatPunchedUdp)
        );
        assert_eq!(
            regime_to_path_kind(AtpLabRegime::ExplicitPublicUdp),
            Some(PathKind::ExplicitPublicUdp)
        );
        assert_eq!(
            regime_to_path_kind(AtpLabRegime::Ipv6Direct),
            Some(PathKind::PublicIpv6)
        );
        assert_eq!(
            regime_to_path_kind(AtpLabRegime::RelayOnly),
            Some(PathKind::AtpRelayUdp)
        );
        assert_eq!(
            regime_to_path_kind(AtpLabRegime::RelayTcpTls443),
            Some(PathKind::AtpRelayTcpTls443)
        );
        assert_eq!(
            regime_to_path_kind(AtpLabRegime::MasqueConnectUdpProxy),
            Some(PathKind::MasqueConnectUdp)
        );
        assert_eq!(
            regime_to_path_kind(AtpLabRegime::OfflineMailbox),
            Some(PathKind::OfflineMailbox)
        );
    }

    #[test]
    fn udp_blocked_regime_forces_fallback_paths() {
        // UDP blocked should not map to any direct path kind
        assert_eq!(regime_to_path_kind(AtpLabRegime::UdpBlocked), None);
    }
}
