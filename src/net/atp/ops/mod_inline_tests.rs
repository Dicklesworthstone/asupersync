    use super::*;

    #[test]
    fn serve_modes_map_to_cli_commands_and_state_machine_configs() {
        let rendezvous =
            AtpRendezvousServeConfig::for_mode(AtpDeploymentMode::Team, "rv-team", "team-ops")
                .expect("team rendezvous config");
        assert_eq!(
            rendezvous.command().words(),
            &["atp", "rendezvous", "serve"]
        );
        assert!(rendezvous.tls().requires_client_auth());
        assert_eq!(rendezvous.quotas().max_total_candidates, 512);

        let state_config = rendezvous
            .rendezvous_service_config()
            .expect("rendezvous service config");
        assert_eq!(state_config.service_id(), "rv-team");
        assert_eq!(state_config.default_quotas().max_total_candidates, 512);
        assert!(!state_config.log_peer_ids());
        assert!(state_config.retain_state_on_restart());

        let relay = AtpRelayServeConfig::for_mode(AtpDeploymentMode::Ci, "relay-ci", "ci-ops")
            .expect("ci relay config");
        assert_eq!(relay.command().words(), &["atp", "relay", "serve"]);
        assert_eq!(relay.max_active_reservations(), 32);
        assert!(!relay.logs().retain_state_on_restart);

        let relay_state = relay.relay_service_config().expect("relay state config");
        assert_eq!(relay_state.relay_id(), "relay-ci");
        assert_eq!(relay_state.max_active_reservations(), 32);
        assert!(relay_state.log_peer_ids());
        assert!(!relay_state.retain_state_on_restart());
    }

    #[test]
    fn config_covers_access_logs_mailbox_quotas_expiry_and_rate_limits() {
        let access = AtpAccessPolicy::private()
            .with_allowed_peer("peer:alice")
            .expect("allowed peer")
            .with_allowed_group("team:infra")
            .expect("allowed group");
        let relay =
            AtpRelayServeConfig::for_mode(AtpDeploymentMode::Team, "relay-team", "team-ops")
                .expect("relay config")
                .with_access_policy(access);

        assert_eq!(relay.access().allowed_peers(), &["peer:alice".to_owned()]);
        assert_eq!(relay.access().allowed_groups(), &["team:infra".to_owned()]);
        assert!(!relay.access().public_registration_enabled());
        assert_eq!(relay.mailbox_storage().storage_label(), "team-mailbox");
        assert!(relay.mailbox_storage().encrypted_only());
        assert!(relay.mailbox_storage().max_bytes() >= 64 * 1024 * MIB);
        assert_eq!(relay.expiry().mailbox_ttl_secs, 604_800);
        assert!(relay.rate_limits().max_packets_per_second >= 200_000);
        assert!(relay.logs().structured_events);
    }

    #[test]
    fn federation_is_disabled_by_default_and_opt_in_requires_trust() {
        let rendezvous =
            AtpRendezvousServeConfig::for_mode(AtpDeploymentMode::Personal, "rv-personal", "me")
                .expect("personal rendezvous");
        assert!(!rendezvous.federation().enabled());

        assert_eq!(
            AtpFederationPolicy::opt_in(Vec::new(), vec!["team roots are pinned".to_owned()])
                .expect_err("trusted service required"),
            AtpOpsConfigError::FederationRequiresTrustedService
        );
        assert_eq!(
            AtpFederationPolicy::opt_in(vec!["rv-team".to_owned()], Vec::new())
                .expect_err("trust assumption required"),
            AtpOpsConfigError::FederationRequiresTrustAssumption
        );

        let federated = rendezvous
            .with_federation_policy(
                AtpFederationPolicy::opt_in(
                    vec!["rv-team".to_owned()],
                    vec!["operators pin each service identity out of band".to_owned()],
                )
                .expect("federation policy"),
            )
            .expect("federated rendezvous config");
        assert!(federated.federation().enabled());
        assert_eq!(
            federated.federation().trusted_services(),
            &["rv-team".to_owned()]
        );
    }

    #[test]
    fn public_gateway_requires_tls_and_relay_visibility_stays_opaque() {
        let relay = AtpRelayServeConfig::for_mode(
            AtpDeploymentMode::PublicGateway,
            "relay-public",
            "public-ops",
        )
        .expect("public relay config");
        assert!(relay.tls().requires_tls());
        assert!(!relay.tls().requires_client_auth());
        assert!(relay.access().public_registration_enabled());
        assert_eq!(
            relay.content_visibility(),
            RelayContentVisibility::OpaqueEncryptedOnly
        );

        assert_eq!(
            relay
                .clone()
                .with_tls_policy(AtpTlsPolicy::DisabledLoopbackOnly)
                .expect_err("public gateway must require TLS"),
            AtpOpsConfigError::PublicGatewayRequiresTls
        );
    }
