    use super::*;
    use std::collections::BTreeSet;

    fn transfer() -> AtpLabTransferSpec {
        AtpLabTransferSpec::new("alice-laptop", "gpu-box", 8 * 1024 * 1024, 3)
    }

    #[test]
    fn required_matrix_covers_acceptance_regimes() {
        let covered: BTreeSet<_> = AtpLabScenario::required_matrix()
            .into_iter()
            .flat_map(|scenario| scenario.regimes)
            .collect();
        let required = BTreeSet::from([
            AtpLabRegime::LanMulticast,
            AtpLabRegime::EasyNat,
            AtpLabRegime::ExplicitPublicUdp,
            AtpLabRegime::HardNat,
            AtpLabRegime::SymmetricNat,
            AtpLabRegime::UdpBlocked,
            AtpLabRegime::Ipv6Direct,
            AtpLabRegime::RelayOnly,
            AtpLabRegime::RelayTcpTls443,
            AtpLabRegime::TailscalePrivateRoute,
            AtpLabRegime::MasqueConnectUdpProxy,
            AtpLabRegime::OfflineMailbox,
            AtpLabRegime::PathMigration,
            AtpLabRegime::PacketDuplication,
            AtpLabRegime::PacketTruncation,
            AtpLabRegime::DelayedAck,
            AtpLabRegime::AckLoss,
            AtpLabRegime::PtoStorm,
            AtpLabRegime::DiskStall,
            AtpLabRegime::Crash,
            AtpLabRegime::MaliciousChunks,
            AtpLabRegime::CorruptedRepairSymbols,
            AtpLabRegime::LyingRelay,
            AtpLabRegime::StalledReceiver,
            AtpLabRegime::Cancellation,
        ]);
        assert_eq!(covered, required);
    }

    #[test]
    fn composed_transfer_plan_is_deterministic() {
        let scenario = AtpLabScenario::new("path-migration", 42)
            .with_regime(AtpLabRegime::PathMigration)
            .with_regime(AtpLabRegime::AckLoss);
        let first = scenario.clone().compose(transfer());
        let second = scenario.compose(transfer());
        assert_eq!(first.events, second.events);
        assert_eq!(first.replay.fingerprint_hex, second.replay.fingerprint_hex);
    }

    #[test]
    fn futurelock_and_leak_oracles_can_be_enabled() {
        let scenario = AtpLabScenario::new("oracles", 7).with_futurelock_and_leak_oracles();
        assert!(scenario.oracle_config.futurelock);
        assert!(scenario.oracle_config.task_leak);
        assert!(scenario.oracle_config.obligation_leak);
        assert!(scenario.oracle_config.region_leak);
    }

    #[test]
    fn failure_preserves_replay_and_minimization_artifacts() {
        let plan = AtpLabScenario::new("adversary", 99)
            .with_regime(AtpLabRegime::LyingRelay)
            .with_artifact_retention()
            .compose(transfer());
        let artifact = plan.run_model();
        assert!(artifact.failure.is_some());
        assert_eq!(artifact.attachments.len(), 2);
        assert!(
            artifact
                .replay
                .minimization_key
                .starts_with("atp-lab-adversary")
        );
        assert!(artifact.attachments[0].text.contains("fault=lying_relay"));
    }

    #[test]
    fn masque_proxy_regime_emits_non_failure_adapter_event() {
        let plan = AtpLabScenario::new("masque-proxy", 0xA7F0_0007)
            .with_regime(AtpLabRegime::MasqueConnectUdpProxy)
            .compose(transfer());

        assert_eq!(plan.events.len(), 1);
        assert_eq!(plan.events[0].fault, AtpLabFault::MasqueProxyPath);
        assert_eq!(plan.events[0].fault.label(), "masque_proxy_path");
        assert!(plan.run_model().failure.is_none());
    }
