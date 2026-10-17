    use super::*;

    fn candidate(raw: u64, kind: PathKind) -> PathCandidate {
        PathCandidate::new(PathCandidateId::new(raw), kind, PathTraceId::new(raw + 100))
    }

    #[test]
    fn path_kind_all_contains_every_candidate_type() {
        assert_eq!(PathKind::ALL.len(), 9);
        assert!(PathKind::ALL.contains(&PathKind::LanMulticast));
        assert!(PathKind::ALL.contains(&PathKind::ExplicitPublicUdp));
        assert!(PathKind::ALL.contains(&PathKind::PublicIpv6));
        assert!(PathKind::ALL.contains(&PathKind::NatPunchedUdp));
        assert!(PathKind::ALL.contains(&PathKind::TailscaleIp));
        assert!(PathKind::ALL.contains(&PathKind::AtpRelayUdp));
        assert!(PathKind::ALL.contains(&PathKind::AtpRelayTcpTls443));
        assert!(PathKind::ALL.contains(&PathKind::MasqueConnectUdp));
        assert!(PathKind::ALL.contains(&PathKind::OfflineMailbox));
    }

    #[test]
    fn security_defaults_distinguish_direct_relay_and_mailbox_paths() {
        let direct = PathSecurity::for_kind(PathKind::NatPunchedUdp);
        assert!(direct.exposes_local_ip_to_peer);
        assert!(!direct.relay_metadata_visible);
        assert!(!direct.store_and_forward);

        let relay = PathSecurity::for_kind(PathKind::AtpRelayTcpTls443);
        assert!(!relay.exposes_local_ip_to_peer);
        assert!(relay.relay_metadata_visible);
        assert!(!relay.store_and_forward);

        let mailbox = PathSecurity::for_kind(PathKind::OfflineMailbox);
        assert!(!mailbox.exposes_local_ip_to_peer);
        assert!(mailbox.relay_metadata_visible);
        assert!(mailbox.store_and_forward);
    }

    #[test]
    fn path_family_classifies_direct_relay_tailscale_and_mailbox() {
        assert_eq!(PathKind::LanMulticast.family(), PathFamily::Direct);
        assert_eq!(PathKind::ExplicitPublicUdp.family(), PathFamily::Direct);
        assert_eq!(PathKind::PublicIpv6.family(), PathFamily::Direct);
        assert_eq!(PathKind::NatPunchedUdp.family(), PathFamily::Direct);
        assert_eq!(PathKind::TailscaleIp.family(), PathFamily::Tailscale);
        assert_eq!(PathKind::AtpRelayUdp.family(), PathFamily::Relay);
        assert_eq!(PathKind::AtpRelayTcpTls443.family(), PathFamily::Relay);
        assert_eq!(PathKind::MasqueConnectUdp.family(), PathFamily::Relay);
        assert_eq!(
            PathKind::OfflineMailbox.family(),
            PathFamily::OfflineMailbox
        );
        assert!(PathKind::PublicIpv6.is_direct());
        assert!(PathKind::AtpRelayTcpTls443.is_relay());
    }

    #[test]
    fn preference_rank_is_a_strict_total_order_tailscale_direct_relay_mailbox() {
        // Every variant has a distinct rank — a strict total order, no ties.
        let mut ranks: Vec<u8> = PathKind::ALL
            .iter()
            .map(|kind| kind.preference_rank())
            .collect();
        let distinct = ranks.len();
        ranks.sort_unstable();
        ranks.dedup();
        assert_eq!(ranks.len(), distinct, "preference_rank must be injective");

        // Sorting all kinds by rank yields Tailscale first, mailbox last.
        let mut sorted = PathKind::ALL;
        sorted.sort_by_key(|kind| kind.preference_rank());
        assert_eq!(sorted[0], PathKind::TailscaleIp);
        assert_eq!(sorted[sorted.len() - 1], PathKind::OfflineMailbox);

        // Tailscale ranks strictly below every other family.
        for kind in PathKind::ALL {
            if kind != PathKind::TailscaleIp {
                assert!(
                    PathKind::TailscaleIp.preference_rank() < kind.preference_rank(),
                    "tailscale must outrank {kind:?}"
                );
            }
        }

        // Every direct variant ranks below every relay variant, and every relay
        // variant ranks below the offline mailbox.
        for direct in PathKind::ALL.iter().filter(|k| k.is_direct()) {
            for relay in PathKind::ALL.iter().filter(|k| k.is_relay()) {
                assert!(
                    direct.preference_rank() < relay.preference_rank(),
                    "direct {direct:?} must outrank relay {relay:?}"
                );
            }
        }
        let mailbox_rank = PathKind::OfflineMailbox.preference_rank();
        for relay in PathKind::ALL.iter().filter(|k| k.is_relay()) {
            assert!(
                relay.preference_rank() < mailbox_rank,
                "relay {relay:?} must outrank the offline mailbox"
            );
        }
        // And every direct variant outranks the mailbox transitively.
        for direct in PathKind::ALL.iter().filter(|k| k.is_direct()) {
            assert!(direct.preference_rank() < mailbox_rank);
        }
    }

    #[test]
    fn masque_connect_udp_adapter_keeps_relay_family_and_proof_caveats() {
        let kind = PathKind::MasqueConnectUdp;
        let security = PathSecurity::for_kind(kind);

        assert_eq!(kind.family(), PathFamily::Relay);
        assert!(kind.is_relay());
        assert!(kind.uses_connect_udp_proxy());
        assert!(kind.has_nested_congestion_caveat());
        assert!(kind.requires_intermediary_authority());
        assert_eq!(kind.proof_summary_label(), "masque_connect_udp_adapter");
        assert_eq!(
            kind.adapter_failure_hint(),
            Some("proxy_auth_policy_or_connect_udp_failure")
        );
        assert!(security.authenticated_peer);
        assert!(security.end_to_end_encrypted);
        assert!(!security.exposes_local_ip_to_peer);
        assert!(security.relay_metadata_visible);
        assert!(!security.store_and_forward);
    }

    #[test]
    fn first_success_wins_and_active_losers_are_drained() {
        let direct = PathCandidateId::new(1);
        let relay = PathCandidateId::new(2);
        let tailscale = PathCandidateId::new(3);
        let mut race = PathRace::new();
        race.add_candidate(candidate(direct.get(), PathKind::NatPunchedUdp))
            .expect("direct candidate");
        race.add_candidate(candidate(relay.get(), PathKind::AtpRelayUdp))
            .expect("relay candidate");
        race.add_candidate(candidate(tailscale.get(), PathKind::TailscaleIp))
            .expect("tailscale candidate");
        race.start_all().expect("start race");

        race.record_outcome(
            relay,
            PathOutcome::success(PathSuccessKind::RelaySelected, 20_000, Some(8_000))
                .with_bytes(240, 240),
        )
        .expect("record relay success");

        assert_eq!(race.winner(), Some(relay));
        assert!(race.all_terminal());
        assert_eq!(race.cleanup_records().len(), 2);
        assert!(
            race.cleanup_records().iter().all(|record| {
                record.winner == relay && record.cancel_requested && record.drained
            })
        );
        assert!(matches!(
            race.candidate(direct).expect("direct").state,
            PathAttemptState::DrainedLoser { winner, .. } if winner == relay
        ));
        assert!(matches!(
            race.candidate(tailscale).expect("tailscale").state,
            PathAttemptState::DrainedLoser { winner, .. } if winner == relay
        ));

        let snapshot = race.diagnostic_snapshot();
        assert_eq!(snapshot.winner, Some(relay));
        assert_eq!(snapshot.selected_kind, Some(PathKind::AtpRelayUdp));
        assert_eq!(snapshot.reason, PathSelectionReason::RelayFallbackValidated);
        assert_eq!(snapshot.reason.code(), "relay_fallback_validated");
        assert_eq!(snapshot.selected_family(), Some(PathFamily::Relay));
        assert_eq!(snapshot.direct_count, 1);
        assert_eq!(snapshot.tailscale_count, 1);
        assert_eq!(snapshot.relay_count, 1);
        assert_eq!(snapshot.drained_loser_count, 2);
    }

    #[test]
    fn failures_do_not_select_winner() {
        let direct = PathCandidateId::new(1);
        let public_ipv6 = PathCandidateId::new(2);
        let mut race = PathRace::new();
        race.add_candidate(candidate(direct.get(), PathKind::NatPunchedUdp))
            .expect("direct candidate");
        race.add_candidate(candidate(public_ipv6.get(), PathKind::PublicIpv6))
            .expect("ipv6 candidate");
        race.start_all().expect("start race");

        race.record_outcome(direct, PathOutcome::failure(PathFailureKind::HardNat, 10))
            .expect("hard nat");
        race.record_outcome(
            public_ipv6,
            PathOutcome::failure(PathFailureKind::UdpBlocked, 12),
        )
        .expect("udp blocked");

        assert_eq!(race.winner(), None);
        assert!(race.all_terminal());
        assert!(race.cleanup_records().is_empty());

        let snapshot = race.diagnostic_snapshot();
        assert_eq!(snapshot.reason, PathSelectionReason::NoSuccessfulCandidate);
        assert_eq!(snapshot.failure_count, 2);
        assert_eq!(snapshot.selected_kind, None);
    }

    #[test]
    fn late_loser_outcome_cannot_replace_winner() {
        let direct = PathCandidateId::new(1);
        let relay = PathCandidateId::new(2);
        let mut race = PathRace::new();
        race.add_candidate(candidate(direct.get(), PathKind::NatPunchedUdp))
            .expect("direct candidate");
        race.add_candidate(candidate(relay.get(), PathKind::AtpRelayUdp))
            .expect("relay candidate");
        race.start_all().expect("start race");

        race.record_outcome(
            direct,
            PathOutcome::success(PathSuccessKind::DirectValidated, 10, Some(3)),
        )
        .expect("direct wins");
        race.record_outcome(
            relay,
            PathOutcome::success(PathSuccessKind::RelaySelected, 11, Some(4)),
        )
        .expect("late loser is drained");

        assert_eq!(race.winner(), Some(direct));
        assert!(matches!(
            race.candidate(relay).expect("relay").state,
            PathAttemptState::DrainedLoser { winner, .. } if winner == direct
        ));

        let snapshot = race.diagnostic_snapshot();
        assert_eq!(
            snapshot.reason,
            PathSelectionReason::DirectCandidateValidated
        );
        assert_eq!(snapshot.selected_kind, Some(PathKind::NatPunchedUdp));
        assert_eq!(snapshot.selected_family(), Some(PathFamily::Direct));
    }

    #[test]
    fn late_winner_outcome_cannot_overwrite_selected_success() {
        let relay = PathCandidateId::new(1);
        let mut race = PathRace::new();
        race.add_candidate(candidate(relay.get(), PathKind::AtpRelayTcpTls443))
            .expect("relay candidate");
        race.start_all().expect("start race");

        race.record_outcome(
            relay,
            PathOutcome::success(PathSuccessKind::RelaySelected, 10, Some(4)).with_bytes(256, 128),
        )
        .expect("relay wins");
        race.record_outcome(
            relay,
            PathOutcome::failure(PathFailureKind::RelayUnavailable, 11),
        )
        .expect("late duplicate outcome is idempotent");

        assert_eq!(race.winner(), Some(relay));
        assert!(matches!(
            race.candidate(relay).expect("relay").state,
            PathAttemptState::Succeeded(outcome)
                if outcome.result == PathOutcomeResult::Success(PathSuccessKind::RelaySelected)
                    && outcome.bytes_sent == 256
                    && outcome.bytes_received == 128
        ));
        let snapshot = race.diagnostic_snapshot();
        assert_eq!(snapshot.success_count, 1);
        assert_eq!(snapshot.failure_count, 0);
        assert_eq!(snapshot.reason, PathSelectionReason::RelayFallbackValidated);
    }

    #[test]
    fn terminal_failures_before_winner_are_not_reclassified_as_drained_losers() {
        let direct = PathCandidateId::new(1);
        let relay = PathCandidateId::new(2);
        let mut race = PathRace::new();
        race.add_candidate(candidate(direct.get(), PathKind::NatPunchedUdp))
            .expect("direct candidate");
        race.add_candidate(candidate(relay.get(), PathKind::AtpRelayUdp))
            .expect("relay candidate");
        race.start_all().expect("start race");

        race.record_outcome(
            direct,
            PathOutcome::failure(PathFailureKind::UdpBlocked, 10),
        )
        .expect("direct failed before relay won");
        race.record_outcome(
            relay,
            PathOutcome::success(PathSuccessKind::RelaySelected, 20, Some(6)),
        )
        .expect("relay wins");
        race.record_outcome(direct, PathOutcome::failure(PathFailureKind::Timeout, 30))
            .expect("late duplicate direct failure is idempotent");

        assert!(matches!(
            race.candidate(direct).expect("direct").state,
            PathAttemptState::Failed(outcome)
                if outcome.result == PathOutcomeResult::Failure(PathFailureKind::UdpBlocked)
        ));
        assert!(race.cleanup_records().is_empty());
        let snapshot = race.diagnostic_snapshot();
        assert_eq!(snapshot.failure_count, 1);
        assert_eq!(snapshot.drained_loser_count, 0);
        assert_eq!(snapshot.reason, PathSelectionReason::RelayFallbackValidated);
    }

    #[test]
    fn diagnostic_snapshot_reports_pending_race() {
        let mut race = PathRace::new();
        race.add_candidate(candidate(1, PathKind::PublicIpv6))
            .expect("ipv6 candidate");
        race.add_candidate(candidate(2, PathKind::TailscaleIp))
            .expect("tailscale candidate");
        race.start_candidate(PathCandidateId::new(1))
            .expect("start ipv6");

        let snapshot = race.diagnostic_snapshot();
        assert_eq!(snapshot.reason, PathSelectionReason::RaceStillPending);
        assert_eq!(snapshot.candidate_count, 2);
        assert_eq!(snapshot.racing_count, 1);
        assert_eq!(snapshot.direct_count, 1);
        assert_eq!(snapshot.tailscale_count, 1);
        assert_eq!(snapshot.selected_kind, None);
    }

    #[test]
    fn policy_denied_is_a_failure_not_success() {
        let outcome = PathOutcome::failure(PathFailureKind::PolicyDenied, 42);
        assert!(!outcome.is_success());
        assert!(matches!(
            outcome.result,
            PathOutcomeResult::Failure(PathFailureKind::PolicyDenied)
        ));
    }

    #[test]
    fn duplicate_candidate_ids_are_rejected() {
        let mut race = PathRace::new();
        let first = candidate(1, PathKind::PublicIpv6);
        let duplicate = candidate(1, PathKind::AtpRelayUdp);
        race.add_candidate(first).expect("first candidate");
        let err = race
            .add_candidate(duplicate)
            .expect_err("duplicate id must fail");
        assert_eq!(
            err,
            PathRaceError::DuplicateCandidate(PathCandidateId::new(1))
        );
    }
