    use super::*;

    #[test]
    fn atp_profile_kinds_have_labels() {
        for kind in AtpProfileKind::all() {
            assert!(!kind.label().is_empty());
            assert!(!kind.description().is_empty());
        }
    }

    #[test]
    fn clean_lan_profile_has_good_conditions() {
        let profile = AtpProfile::clean_lan();
        assert_eq!(profile.kind, AtpProfileKind::CleanLan);
        assert!(profile.network_conditions.latency <= Duration::from_millis(5));
        assert!(profile.network_conditions.packet_loss < 0.001);
    }

    #[test]
    fn lossy_wifi_profile_has_challenging_conditions() {
        let profile = AtpProfile::lossy_wifi();
        assert_eq!(profile.kind, AtpProfileKind::LossyWifi);
        assert!(profile.network_conditions.packet_loss > 0.01);
        assert!(profile.network_conditions.jitter > Duration::ZERO);
    }

    #[test]
    fn smoke_test_suitable_profiles_are_reasonable() {
        for kind in AtpProfileKind::all() {
            if kind.is_smoke_test_suitable() {
                // Smoke test profiles should be relatively fast
                assert!(matches!(
                    kind,
                    AtpProfileKind::CleanLan | AtpProfileKind::Wan | AtpProfileKind::Stream
                ));
            }
        }
    }
