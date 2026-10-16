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
