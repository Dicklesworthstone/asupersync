    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::super::morphism::{
        ResponsePolicy, ReversibilityRequirement, SharingPolicy, SubjectTransform,
    };
    use super::*;
    use crate::types::{Budget, RegionId, TaskId};
    use crate::util::ArenaIndex;

    fn derived_view_morphism() -> Morphism {
        Morphism::default()
    }

    fn authoritative_morphism() -> Morphism {
        Morphism {
            class: MorphismClass::Authoritative,
            reversibility: ReversibilityRequirement::Bijective,
            capability_requirements: vec![FabricCapability::CarryAuthority],
            response_policy: ResponsePolicy::ReplyAuthoritative,
            ..Morphism::default()
        }
    }

    fn region_id(n: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(n, 0))
    }

    fn snapshot_auth_key() -> AuthKey {
        AuthKey::from_seed(0xFEDE_A710)
    }

    fn task_id(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn replay_artifact(
        artifact_id: &str,
        family: SystemSubjectFamily,
        captured_secs: u64,
        sequence: u64,
    ) -> ReplayArtifactRecord {
        ReplayArtifactRecord {
            artifact_id: artifact_id.to_owned(),
            family,
            captured_at: Duration::from_secs(captured_secs),
            sequence,
            bytes: 256,
        }
    }

    fn distributed_node(
        node_id: &str,
        service: &str,
        failure_domain: &str,
    ) -> DistributedSupervisionNodeSpec {
        DistributedSupervisionNodeSpec::new(
            node_id,
            "acme",
            service,
            failure_domain,
            64,
            DistributedRestartEnvelope::restart(3, Duration::from_secs(45)),
        )
        .expect("distributed node should be valid")
    }

    fn rename_mailbox_prefix(service: &str, replacement: &str) -> Morphism {
        let mut morphism = derived_view_morphism();
        morphism.transform = SubjectTransform::RenamePrefix {
            from: SubjectPattern::new(format!("tenant.acme.service.{service}.mailbox")),
            to: SubjectPattern::new(format!("tenant.acme.service.{service}.{replacement}")),
        };
        morphism
    }

    #[test]
    fn leaf_bridge_accepts_constrained_morphisms() {
        let bridge = FederationBridge::new(
            FederationRole::LeafFabric(LeafConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .expect("leaf bridge should accept bounded derived-view morphisms");

        assert_eq!(bridge.role.name(), "leaf_fabric");
        assert_eq!(bridge.state, FederationBridgeState::Provisioning);
    }

    #[test]
    fn leaf_bridge_rejects_disallowed_authoritative_morphism() {
        let err = FederationBridge::new(
            FederationRole::LeafFabric(LeafConfig::default()),
            vec![authoritative_morphism()],
            Vec::new(),
            [FabricCapability::CarryAuthority],
        )
        .expect_err("leaf bridge should reject authoritative morphisms");

        assert_eq!(
            err,
            FederationError::LeafMorphismClassNotAllowed {
                class: MorphismClass::Authoritative,
            }
        );
    }

    #[test]
    fn gateway_config_rejects_zero_convergence_timeout() {
        let role = FederationRole::GatewayFabric(GatewayConfig {
            convergence_timeout: Duration::ZERO,
            ..GatewayConfig::default()
        });

        let err = role
            .validate()
            .expect_err("zero convergence timeout must be rejected");

        assert_eq!(
            err,
            FederationError::ZeroDuration {
                field: "role.gateway_fabric.convergence_timeout".to_owned(),
            }
        );
    }

    #[test]
    fn gateway_bridge_rejects_morphism_fanout_above_limit() {
        let mut morphism = derived_view_morphism();
        morphism.quota_policy.max_fanout = 9;
        let role = FederationRole::GatewayFabric(GatewayConfig {
            amplification_limit: 4,
            ..GatewayConfig::default()
        });

        let err = FederationBridge::new(
            role,
            vec![morphism],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .expect_err("gateway should reject excessive fanout");

        assert_eq!(
            err,
            FederationError::GatewayAmplificationExceeded { actual: 9, max: 4 }
        );
    }

    #[test]
    fn edge_replay_bridge_requires_observe_evidence_capability() {
        let err = FederationBridge::new(
            FederationRole::EdgeReplayLink(EdgeReplayConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .expect_err("edge replay should require evidence capability");

        assert_eq!(err, FederationError::EdgeReplayRequiresObserveEvidence);
    }

    #[test]
    fn bridge_lifecycle_moves_through_active_degraded_and_closed_states() {
        let mut bridge = FederationBridge::new(
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .expect("replication bridge should be valid");

        bridge.activate().expect("bridge should activate");
        assert_eq!(bridge.state, FederationBridgeState::Active);

        bridge
            .mark_degraded()
            .expect("bridge should enter degraded state");
        assert_eq!(bridge.state, FederationBridgeState::Degraded);

        bridge.activate().expect("bridge should reactivate");
        assert_eq!(bridge.state, FederationBridgeState::Active);

        bridge.close();
        assert_eq!(bridge.state, FederationBridgeState::Closed);
        assert_eq!(
            bridge
                .activate()
                .expect_err("closed bridge must not reactivate"),
            FederationError::CannotActivateClosedBridge
        );
    }

    // ========================================================================
    // Comprehensive federation tests (bead 8w83i.11.3)
    // ========================================================================

    // -- MorphismConstraints validation --------------------------------------

    #[test]
    fn morphism_constraints_default_allows_derived_view_and_egress() {
        let mc = MorphismConstraints::default();
        assert!(mc.allowed_classes.contains(&MorphismClass::DerivedView));
        assert!(mc.allowed_classes.contains(&MorphismClass::Egress));
        assert_eq!(mc.allowed_classes.len(), 2);
        assert!(mc.validate().is_ok());
    }

    #[test]
    fn morphism_constraints_rejects_empty_allowed_classes() {
        let mc = MorphismConstraints {
            allowed_classes: BTreeSet::new(),
            ..MorphismConstraints::default()
        };
        assert_eq!(
            mc.validate().unwrap_err(),
            FederationError::EmptyAllowedMorphismClasses
        );
    }

    #[test]
    fn morphism_constraints_rejects_zero_expansion_factor() {
        let mc = MorphismConstraints {
            max_expansion_factor: 0,
            ..MorphismConstraints::default()
        };
        assert_eq!(
            mc.validate().unwrap_err(),
            FederationError::ZeroMaxExpansionFactor
        );
    }

    #[test]
    fn morphism_constraints_rejects_zero_fanout() {
        let mc = MorphismConstraints {
            max_fanout: 0,
            ..MorphismConstraints::default()
        };
        assert_eq!(mc.validate().unwrap_err(), FederationError::ZeroMaxFanout);
    }

    #[test]
    fn morphism_constraints_admits_within_bounds() {
        let mc = MorphismConstraints::default();
        let m = derived_view_morphism();
        assert!(mc.admits(&m).is_ok());
    }

    #[test]
    fn morphism_constraints_rejects_expansion_factor_exceeded() {
        let mc = MorphismConstraints {
            max_expansion_factor: 2,
            ..MorphismConstraints::default()
        };
        let mut m = derived_view_morphism();
        m.quota_policy.max_expansion_factor = 5;
        match mc.admits(&m) {
            Err(FederationError::LeafExpansionFactorExceeded { actual, max }) => {
                assert_eq!(actual, 5);
                assert_eq!(max, 2);
            }
            other => panic!("expected LeafExpansionFactorExceeded, got {other:?}"),
        }
    }

    #[test]
    fn morphism_constraints_rejects_fanout_exceeded() {
        let mc = MorphismConstraints {
            max_fanout: 3,
            ..MorphismConstraints::default()
        };
        let mut m = derived_view_morphism();
        m.quota_policy.max_fanout = 10;
        match mc.admits(&m) {
            Err(FederationError::LeafFanoutExceeded { actual, max }) => {
                assert_eq!(actual, 10);
                assert_eq!(max, 3);
            }
            other => panic!("expected LeafFanoutExceeded, got {other:?}"),
        }
    }

    // -- LeafConfig validation -----------------------------------------------

    #[test]
    fn leaf_config_default_validates() {
        let config = LeafConfig::default();
        assert!(config.validate().is_ok());
        assert!(config.max_reconnect_backoff > Duration::ZERO);
        assert!(config.offline_buffer_limit > 0);
    }

    #[test]
    fn leaf_config_rejects_zero_reconnect_backoff() {
        let config = LeafConfig {
            max_reconnect_backoff: Duration::ZERO,
            ..LeafConfig::default()
        };
        match config.validate() {
            Err(FederationError::ZeroDuration { field }) => {
                assert!(field.contains("max_reconnect_backoff"));
            }
            other => panic!("expected ZeroDuration, got {other:?}"),
        }
    }

    #[test]
    fn leaf_config_rejects_zero_offline_buffer() {
        let config = LeafConfig {
            offline_buffer_limit: 0,
            ..LeafConfig::default()
        };
        assert_eq!(
            config.validate().unwrap_err(),
            FederationError::ZeroOfflineBufferLimit
        );
    }

    // -- GatewayConfig validation --------------------------------------------

    #[test]
    fn gateway_config_default_validates() {
        let config = GatewayConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(
            config.interest_propagation_policy,
            InterestPropagationPolicy::DemandDriven
        );
    }

    #[test]
    fn gateway_config_rejects_zero_amplification_limit() {
        let config = GatewayConfig {
            amplification_limit: 0,
            ..GatewayConfig::default()
        };
        assert_eq!(
            config.validate().unwrap_err(),
            FederationError::ZeroAmplificationLimit
        );
    }

    // -- ReplicationConfig validation ----------------------------------------

    #[test]
    fn replication_config_default_validates() {
        let config = ReplicationConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.ordering_guarantee, OrderingGuarantee::PerSubject);
        assert_eq!(config.catch_up_policy, CatchUpPolicy::SnapshotThenDelta);
    }

    #[test]
    fn replication_config_rejects_zero_snapshot_interval() {
        let config = ReplicationConfig {
            snapshot_interval: Duration::ZERO,
            ..ReplicationConfig::default()
        };
        match config.validate() {
            Err(FederationError::ZeroDuration { field }) => {
                assert!(field.contains("snapshot_interval"));
            }
            other => panic!("expected ZeroDuration, got {other:?}"),
        }
    }

    // -- TraceRetention validation -------------------------------------------

    #[test]
    fn trace_retention_default_validates() {
        let retention = TraceRetention::default();
        assert!(retention.validate().is_ok());
        assert!(matches!(
            retention,
            TraceRetention::LatestArtifacts { max_artifacts: 128 }
        ));
    }

    #[test]
    fn trace_retention_rejects_zero_artifacts() {
        let retention = TraceRetention::LatestArtifacts { max_artifacts: 0 };
        assert_eq!(
            retention.validate().unwrap_err(),
            FederationError::ZeroTraceArtifactLimit
        );
    }

    #[test]
    fn trace_retention_rejects_zero_duration_window() {
        let retention = TraceRetention::DurationWindow {
            retention: Duration::ZERO,
        };
        match retention.validate() {
            Err(FederationError::ZeroDuration { .. }) => {}
            other => panic!("expected ZeroDuration, got {other:?}"),
        }
    }

    #[test]
    fn trace_retention_until_acknowledged_validates() {
        let retention = TraceRetention::UntilAcknowledged;
        assert!(retention.validate().is_ok());
    }

    // -- EdgeReplayConfig validation -----------------------------------------

    #[test]
    fn edge_replay_config_default_validates() {
        let config = EdgeReplayConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(
            config.evidence_shipping_policy,
            EvidenceShippingPolicy::OnReconnect
        );
        assert!(config.reconnection_replay_depth > 0);
    }

    #[test]
    fn edge_replay_config_rejects_zero_replay_depth() {
        let config = EdgeReplayConfig {
            reconnection_replay_depth: 0,
            ..EdgeReplayConfig::default()
        };
        assert_eq!(
            config.validate().unwrap_err(),
            FederationError::ZeroReplayDepth
        );
    }

    // -- FederationRole name and validation -----------------------------------

    #[test]
    fn all_role_names_are_distinct() {
        let roles = [
            FederationRole::LeafFabric(LeafConfig::default()),
            FederationRole::GatewayFabric(GatewayConfig::default()),
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            FederationRole::EdgeReplayLink(EdgeReplayConfig::default()),
        ];
        let mut names: Vec<&str> = roles.iter().map(super::FederationRole::name).collect();
        let orig = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), orig, "role names must be unique");
    }

    #[test]
    fn all_default_role_configs_validate() {
        let roles = [
            FederationRole::LeafFabric(LeafConfig::default()),
            FederationRole::GatewayFabric(GatewayConfig::default()),
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            FederationRole::EdgeReplayLink(EdgeReplayConfig::default()),
        ];
        for role in &roles {
            assert!(
                role.validate().is_ok(),
                "role {} default config should validate",
                role.name()
            );
        }
    }

    // -- FederationBridge construction ----------------------------------------

    #[test]
    fn bridge_rejects_empty_capability_scope() {
        let err = FederationBridge::new(
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            Vec::<FabricCapability>::new(),
        )
        .unwrap_err();
        assert_eq!(err, FederationError::EmptyCapabilityScope);
    }

    #[test]
    fn bridge_rejects_empty_morphism_set() {
        let err = FederationBridge::new(
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            Vec::new(),
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .unwrap_err();
        assert_eq!(err, FederationError::EmptyMorphismSet);
    }

    #[test]
    fn bridge_rejects_missing_capability_for_morphism() {
        let err = FederationBridge::new(
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            vec![authoritative_morphism()],
            Vec::new(),
            // Missing CarryAuthority
            [FabricCapability::RewriteNamespace],
        )
        .unwrap_err();
        assert_eq!(
            err,
            FederationError::CapabilityScopeMissing {
                capability: FabricCapability::CarryAuthority,
            }
        );
    }

    #[test]
    fn bridge_accepts_morphisms_on_remote_side_only() {
        let bridge = FederationBridge::new(
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            Vec::new(),
            vec![derived_view_morphism()],
            [FabricCapability::RewriteNamespace],
        )
        .expect("remote-only morphisms should be accepted");
        assert!(bridge.local_morphisms.is_empty());
        assert_eq!(bridge.remote_morphisms.len(), 1);
    }

    #[test]
    fn bridge_accepts_morphisms_on_both_sides() {
        let bridge = FederationBridge::new(
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            vec![derived_view_morphism()],
            vec![derived_view_morphism()],
            [FabricCapability::RewriteNamespace],
        )
        .expect("morphisms on both sides should be accepted");
        assert_eq!(bridge.local_morphisms.len(), 1);
        assert_eq!(bridge.remote_morphisms.len(), 1);
    }

    #[test]
    fn edge_replay_bridge_succeeds_with_observe_evidence() {
        let bridge = FederationBridge::new(
            FederationRole::EdgeReplayLink(EdgeReplayConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            [
                FabricCapability::RewriteNamespace,
                FabricCapability::ObserveEvidence,
            ],
        )
        .expect("edge replay with ObserveEvidence should succeed");
        assert_eq!(bridge.role.name(), "edge_replay_link");
    }

    // -- Bridge lifecycle edge cases -----------------------------------------

    #[test]
    fn bridge_starts_in_provisioning() {
        let bridge = FederationBridge::new(
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .unwrap();
        assert_eq!(bridge.state, FederationBridgeState::Provisioning);
    }

    #[test]
    fn closed_bridge_cannot_be_degraded() {
        let mut bridge = FederationBridge::new(
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .unwrap();
        bridge.close();
        assert_eq!(
            bridge.mark_degraded().unwrap_err(),
            FederationError::CannotDegradeClosedBridge
        );
    }

    #[test]
    fn degraded_bridge_can_be_reactivated() {
        let mut bridge = FederationBridge::new(
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .unwrap();
        bridge.mark_degraded().unwrap();
        bridge
            .activate()
            .expect("degraded bridge should reactivate");
        assert_eq!(bridge.state, FederationBridgeState::Active);
    }

    // -- Serialization round-trips -------------------------------------------

    #[test]
    fn leaf_config_json_round_trip() {
        let config = LeafConfig::default();
        let json = serde_json::to_string(&config).expect("serialize");
        let roundtrip: LeafConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, roundtrip);
    }

    #[test]
    fn gateway_config_json_round_trip() {
        let config = GatewayConfig::default();
        let json = serde_json::to_string(&config).expect("serialize");
        let roundtrip: GatewayConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, roundtrip);
    }

    #[test]
    fn replication_config_json_round_trip() {
        let config = ReplicationConfig::default();
        let json = serde_json::to_string(&config).expect("serialize");
        let roundtrip: ReplicationConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, roundtrip);
    }

    #[test]
    fn edge_replay_config_json_round_trip() {
        let config = EdgeReplayConfig::default();
        let json = serde_json::to_string(&config).expect("serialize");
        let roundtrip: EdgeReplayConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, roundtrip);
    }

    #[test]
    fn federation_role_tagged_json_round_trip() {
        for role in [
            FederationRole::LeafFabric(LeafConfig::default()),
            FederationRole::GatewayFabric(GatewayConfig::default()),
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            FederationRole::EdgeReplayLink(EdgeReplayConfig::default()),
        ] {
            let json = serde_json::to_string(&role).expect("serialize");
            let roundtrip: FederationRole = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(role, roundtrip);
        }
    }

    #[test]
    fn bridge_state_json_round_trip() {
        for state in [
            FederationBridgeState::Provisioning,
            FederationBridgeState::Active,
            FederationBridgeState::Degraded,
            FederationBridgeState::Closed,
        ] {
            let json = serde_json::to_string(&state).expect("serialize");
            let roundtrip: FederationBridgeState =
                serde_json::from_str(&json).expect("deserialize");
            assert_eq!(state, roundtrip);
        }
    }

    #[test]
    fn federation_bridge_json_round_trip_preserves_config_and_resets_ephemeral_runtime() {
        let mut bridge = FederationBridge::new(
            FederationRole::LeafFabric(LeafConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .unwrap();
        bridge.mark_degraded().unwrap();
        let _ = bridge
            .queue_leaf_route(
                FederationDirection::LocalToRemote,
                SubjectPattern::new("tenant.audit.>"),
                1,
            )
            .unwrap();

        let json = serde_json::to_string(&bridge).expect("serialize bridge");
        let roundtrip: FederationBridge = serde_json::from_str(&json).expect("deserialize bridge");
        assert_eq!(bridge.role, roundtrip.role);
        assert_eq!(bridge.local_morphisms, roundtrip.local_morphisms);
        assert_eq!(bridge.remote_morphisms, roundtrip.remote_morphisms);
        assert_eq!(bridge.capability_scope, roundtrip.capability_scope);
        assert_eq!(bridge.state, roundtrip.state);
        assert!(roundtrip.runtime.is_none());
        assert_eq!(
            roundtrip.runtime(),
            FederationBridgeRuntime::Leaf(LeafBridgeRuntime::default())
        );
        assert_ne!(bridge.runtime(), roundtrip.runtime());
        assert_eq!(bridge, roundtrip);
    }

    #[test]
    fn federation_bridge_pristine_round_trip_preserves_normalized_equality() {
        let bridge = FederationBridge::new(
            FederationRole::GatewayFabric(GatewayConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .unwrap();

        let json = serde_json::to_string(&bridge).expect("serialize bridge");
        let roundtrip: FederationBridge = serde_json::from_str(&json).expect("deserialize bridge");

        assert!(roundtrip.runtime.is_none());
        assert_eq!(bridge.runtime(), roundtrip.runtime());
        assert_eq!(bridge, roundtrip);
    }

    #[test]
    fn federation_bridge_equality_ignores_ephemeral_runtime_state() {
        let mut buffered = FederationBridge::new(
            FederationRole::LeafFabric(LeafConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .unwrap();
        let mut pristine = FederationBridge::new(
            FederationRole::LeafFabric(LeafConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .unwrap();

        buffered.mark_degraded().unwrap();
        pristine.mark_degraded().unwrap();
        let _ = buffered
            .queue_leaf_route(
                FederationDirection::LocalToRemote,
                SubjectPattern::new("tenant.audit.>"),
                1,
            )
            .unwrap();

        assert_ne!(buffered.runtime(), pristine.runtime());
        assert_eq!(buffered, pristine);
    }

    #[test]
    fn interest_propagation_all_variants_json_round_trip() {
        for policy in [
            InterestPropagationPolicy::ExplicitSubscriptions,
            InterestPropagationPolicy::PrefixAnnouncements,
            InterestPropagationPolicy::DemandDriven,
        ] {
            let json = serde_json::to_string(&policy).expect("serialize");
            let roundtrip: InterestPropagationPolicy =
                serde_json::from_str(&json).expect("deserialize");
            assert_eq!(policy, roundtrip);
        }
    }

    #[test]
    fn ordering_guarantee_all_variants_json_round_trip() {
        for guarantee in [
            OrderingGuarantee::PerSubject,
            OrderingGuarantee::SnapshotConsistent,
            OrderingGuarantee::CheckpointBounded,
        ] {
            let json = serde_json::to_string(&guarantee).expect("serialize");
            let roundtrip: OrderingGuarantee = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(guarantee, roundtrip);
        }
    }

    #[test]
    fn catch_up_policy_all_variants_json_round_trip() {
        for policy in [
            CatchUpPolicy::SnapshotRequired,
            CatchUpPolicy::SnapshotThenDelta,
            CatchUpPolicy::LogOnly,
        ] {
            let json = serde_json::to_string(&policy).expect("serialize");
            let roundtrip: CatchUpPolicy = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(policy, roundtrip);
        }
    }

    #[test]
    fn trace_retention_all_variants_json_round_trip() {
        for retention in [
            TraceRetention::LatestArtifacts { max_artifacts: 42 },
            TraceRetention::DurationWindow {
                retention: Duration::from_secs(3600),
            },
            TraceRetention::UntilAcknowledged,
        ] {
            let json = serde_json::to_string(&retention).expect("serialize");
            let roundtrip: TraceRetention = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(retention, roundtrip);
        }
    }

    // -- FederationBridgeState ordering --------------------------------------

    #[test]
    fn bridge_states_have_consistent_ordering() {
        assert!(FederationBridgeState::Provisioning < FederationBridgeState::Active);
        assert!(FederationBridgeState::Active < FederationBridgeState::Degraded);
        assert!(FederationBridgeState::Degraded < FederationBridgeState::Closed);
    }

    // -- Gateway amplification enforcement -----------------------------------

    #[test]
    fn gateway_bridge_accepts_morphism_within_limit() {
        let mut morphism = derived_view_morphism();
        morphism.quota_policy.max_fanout = 4;
        let bridge = FederationBridge::new(
            FederationRole::GatewayFabric(GatewayConfig {
                amplification_limit: 4,
                ..GatewayConfig::default()
            }),
            vec![morphism],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .expect("gateway should accept morphism at limit boundary");
        assert_eq!(bridge.role.name(), "gateway_fabric");
    }

    // -- Leaf boundary morphism class enforcement ----------------------------

    #[test]
    fn leaf_accepts_egress_morphism() {
        let mut morphism = derived_view_morphism();
        morphism.class = MorphismClass::Egress;
        morphism.response_policy = ResponsePolicy::StripReplies;
        morphism.reversibility = ReversibilityRequirement::Irreversible;
        morphism.sharing_policy = SharingPolicy::Federated;
        let bridge = FederationBridge::new(
            FederationRole::LeafFabric(LeafConfig::default()),
            vec![morphism],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .expect("leaf should accept egress morphisms");
        assert_eq!(bridge.role.name(), "leaf_fabric");
    }

    // -- Role-specific bridge operations ------------------------------------

    #[test]
    fn leaf_bridge_buffers_routes_until_reactivation() {
        let mut bridge = FederationBridge::new(
            FederationRole::LeafFabric(LeafConfig {
                offline_buffer_limit: 2,
                ..LeafConfig::default()
            }),
            vec![derived_view_morphism()],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .unwrap();
        bridge.mark_degraded().unwrap();

        let first = bridge
            .queue_leaf_route(
                FederationDirection::LocalToRemote,
                SubjectPattern::new("tenant.alpha.>"),
                1,
            )
            .unwrap();
        let second = bridge
            .queue_leaf_route(
                FederationDirection::LocalToRemote,
                SubjectPattern::new("tenant.beta.>"),
                1,
            )
            .unwrap();
        let third = bridge
            .queue_leaf_route(
                FederationDirection::RemoteToLocal,
                SubjectPattern::new("tenant.gamma.>"),
                1,
            )
            .unwrap();

        assert!(matches!(
            first,
            LeafRouteDisposition::Buffered {
                buffered_entries: 1,
                dropped_entries: 0,
                ..
            }
        ));
        assert!(matches!(
            second,
            LeafRouteDisposition::Buffered {
                buffered_entries: 2,
                dropped_entries: 0,
                ..
            }
        ));
        assert!(matches!(
            third,
            LeafRouteDisposition::Buffered {
                buffered_entries: 2,
                dropped_entries: 1,
                ..
            }
        ));

        bridge.activate().unwrap();
        let drain = bridge.drain_leaf_buffer().unwrap();
        let drained_subjects: Vec<&str> = drain
            .routes
            .iter()
            .map(|route| route.subject.as_str())
            .collect();
        assert_eq!(drain.dropped_entries, 1);
        assert_eq!(drained_subjects, vec!["tenant.beta.>", "tenant.gamma.>"]);
    }

    #[test]
    fn gateway_bridge_applies_budgeted_interest_and_convergence() {
        let mut bridge = FederationBridge::new(
            FederationRole::GatewayFabric(GatewayConfig {
                amplification_limit: 4,
                convergence_timeout: Duration::from_secs(5),
                ..GatewayConfig::default()
            }),
            vec![derived_view_morphism()],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .unwrap();
        bridge.activate().unwrap();

        let err = bridge
            .plan_gateway_interest(
                SystemSubjectFamily::Route,
                SubjectPattern::new("tenant.route.>"),
                5,
                ControlBudget {
                    poll_quota: 3,
                    ..ControlBudget::default()
                },
            )
            .unwrap_err();
        assert_eq!(
            err,
            FederationError::GatewayAmplificationExceeded { actual: 5, max: 3 }
        );

        let plan = bridge
            .plan_gateway_interest(
                SystemSubjectFamily::Route,
                SubjectPattern::new("tenant.route.>"),
                2,
                ControlBudget {
                    poll_quota: 3,
                    ..ControlBudget::default()
                },
            )
            .unwrap();
        assert_eq!(plan.admitted_amplification, 2);

        let advisory = bridge
            .forward_gateway_advisory(
                SystemSubjectFamily::Replay,
                SubjectPattern::new("$SYS.FABRIC.REPLAY.>"),
                ControlBudget::default(),
            )
            .unwrap();
        assert_eq!(advisory.family, SystemSubjectFamily::Replay);

        let convergence = bridge
            .reconcile_gateway_convergence(Duration::from_secs(6))
            .unwrap();
        assert!(convergence.timed_out);
        assert_eq!(bridge.state, FederationBridgeState::Degraded);

        match bridge.runtime() {
            FederationBridgeRuntime::Gateway(runtime) => {
                assert!(
                    runtime
                        .propagated_interests
                        .contains(&GatewayInterestRecord {
                            family: SystemSubjectFamily::Route,
                            pattern: SubjectPattern::new("tenant.route.>"),
                        })
                );
                assert_eq!(runtime.forwarded_advisories.len(), 1);
            }
            other => panic!("expected gateway runtime, got {other:?}"),
        }
    }

    #[test]
    fn gateway_runtime_distinguishes_interest_family_from_pattern() {
        let mut bridge = FederationBridge::new(
            FederationRole::GatewayFabric(GatewayConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .unwrap();
        bridge.activate().unwrap();

        bridge
            .plan_gateway_interest(
                SystemSubjectFamily::Route,
                SubjectPattern::new("tenant.shared.>"),
                1,
                ControlBudget::default(),
            )
            .unwrap();
        bridge
            .plan_gateway_interest(
                SystemSubjectFamily::Replay,
                SubjectPattern::new("tenant.shared.>"),
                1,
                ControlBudget::default(),
            )
            .unwrap();

        match bridge.runtime() {
            FederationBridgeRuntime::Gateway(runtime) => {
                assert_eq!(runtime.propagated_interests.len(), 2);
            }
            other => panic!("expected gateway runtime, got {other:?}"),
        }
    }

    #[test]
    fn replication_bridge_exports_and_applies_region_snapshots() {
        let mut federation = FederationBridge::new(
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .unwrap();

        let region = region_id(10);
        let mut source = RegionBridge::new_local(region, None, Budget::new());
        source.add_task(task_id(11)).unwrap();
        source.add_child(region_id(12)).unwrap();
        let snapshot_auth_key = snapshot_auth_key();

        let transfer = federation
            .export_replication_transfer(&mut source, Time::from_secs(1), &snapshot_auth_key)
            .unwrap();
        assert_eq!(transfer.sequence, 1);

        let mut target = RegionBridge::new_local(region, None, Budget::new());
        let applied = federation
            .apply_replication_transfer(&mut target, &transfer, &snapshot_auth_key)
            .unwrap();
        assert_eq!(applied.sequence, 1);
        assert_eq!(target.local().task_ids(), vec![task_id(11)]);
        assert_eq!(target.local().child_ids(), vec![region_id(12)]);

        match federation.runtime() {
            FederationBridgeRuntime::Replication(runtime) => {
                assert_eq!(runtime.last_exported_sequence, Some(1));
                assert_eq!(runtime.last_applied_sequence, Some(1));
            }
            other => panic!("expected replication runtime, got {other:?}"),
        }
    }

    #[test]
    fn replication_bridge_catch_up_plan_respects_policy() {
        let mut log_only = FederationBridge::new(
            FederationRole::ReplicationLink(ReplicationConfig {
                catch_up_policy: CatchUpPolicy::LogOnly,
                ..ReplicationConfig::default()
            }),
            vec![derived_view_morphism()],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .unwrap();
        let mut snapshot_required = FederationBridge::new(
            FederationRole::ReplicationLink(ReplicationConfig {
                catch_up_policy: CatchUpPolicy::SnapshotRequired,
                ..ReplicationConfig::default()
            }),
            vec![derived_view_morphism()],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .unwrap();

        let log_plan = log_only.plan_replication_catch_up(10, 4).unwrap();
        let snapshot_plan = snapshot_required.plan_replication_catch_up(10, 4).unwrap();

        assert_eq!(log_plan.action, ReplicationCatchUpAction::DeltaOnly);
        assert_eq!(snapshot_plan.action, ReplicationCatchUpAction::Snapshot);
    }

    #[test]
    fn replication_bridge_rejects_remote_ahead_catch_up_plan() {
        let mut federation = FederationBridge::new(
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .unwrap();

        let err = federation.plan_replication_catch_up(4, 7).unwrap_err();
        assert_eq!(
            err,
            FederationError::ReplicationCatchUpRemoteAhead {
                local_sequence: 4,
                remote_sequence: 7,
            }
        );

        match federation.runtime() {
            FederationBridgeRuntime::Replication(runtime) => {
                assert_eq!(runtime.last_catch_up, None);
            }
            other => panic!("expected replication runtime, got {other:?}"),
        }
    }

    #[test]
    fn replication_bridge_rejects_mismatched_transfer_metadata() {
        let mut federation = FederationBridge::new(
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .unwrap();

        let region = region_id(20);
        let mut source = RegionBridge::new_local(region, None, Budget::new());
        source.add_task(task_id(21)).unwrap();
        let snapshot_auth_key = snapshot_auth_key();

        let mut transfer = federation
            .export_replication_transfer(&mut source, Time::from_secs(2), &snapshot_auth_key)
            .unwrap();
        transfer.sequence += 1;

        let mut target = RegionBridge::new_local(region, None, Budget::new());
        let err = federation
            .apply_replication_transfer(&mut target, &transfer, &snapshot_auth_key)
            .unwrap_err();
        assert_eq!(
            err,
            FederationError::ReplicationTransferSequenceMismatch {
                expected: 2,
                actual: 1,
            }
        );
    }

    #[test]
    fn replication_bridge_rejects_forged_snapshot_with_recomputed_hash() {
        let mut federation = FederationBridge::new(
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .unwrap();

        let region = region_id(30);
        let mut source = RegionBridge::new_local(region, None, Budget::new());
        source.add_task(task_id(31)).unwrap();
        let snapshot_auth_key = snapshot_auth_key();
        let mut transfer = federation
            .export_replication_transfer(&mut source, Time::from_secs(3), &snapshot_auth_key)
            .unwrap();

        let mut forged = RegionSnapshot::from_bytes(&transfer.snapshot_bytes).unwrap();
        forged.tasks.clear();
        forged.metadata = b"attacker-controlled state".to_vec();
        forged.sign(&AuthKey::from_seed(0xBAD0_CAFE));
        transfer.snapshot_hash = forged.content_hash().to_hex();
        transfer.snapshot_bytes = forged.to_bytes();

        let mut target = RegionBridge::new_local(region, None, Budget::new());
        let err = federation
            .apply_replication_transfer(&mut target, &transfer, &snapshot_auth_key)
            .unwrap_err();

        assert!(matches!(
            err,
            FederationError::SnapshotDecode(SnapshotError::AuthenticationFailed)
        ));
        assert!(target.local().task_ids().is_empty());
    }

    #[test]
    fn edge_replay_bridge_retains_latest_artifacts_and_ships_on_reconnect() {
        let mut bridge = FederationBridge::new(
            FederationRole::EdgeReplayLink(EdgeReplayConfig {
                trace_retention: TraceRetention::LatestArtifacts { max_artifacts: 2 },
                evidence_shipping_policy: EvidenceShippingPolicy::OnReconnect,
                reconnection_replay_depth: 2,
            }),
            vec![derived_view_morphism()],
            Vec::new(),
            [
                FabricCapability::RewriteNamespace,
                FabricCapability::ObserveEvidence,
            ],
        )
        .unwrap();

        bridge
            .retain_replay_artifact(replay_artifact(
                "artifact-a",
                SystemSubjectFamily::Replay,
                1,
                1,
            ))
            .unwrap();
        bridge
            .retain_replay_artifact(replay_artifact(
                "artifact-b",
                SystemSubjectFamily::Replay,
                2,
                2,
            ))
            .unwrap();
        bridge
            .retain_replay_artifact(replay_artifact(
                "artifact-c",
                SystemSubjectFamily::Replay,
                3,
                3,
            ))
            .unwrap();

        let before_reconnect = bridge.plan_replay_shipping().unwrap();
        assert!(before_reconnect.artifacts.is_empty());

        bridge.activate().unwrap();
        let shipping = bridge.plan_replay_shipping().unwrap();
        let shipped_ids: Vec<&str> = shipping
            .artifacts
            .iter()
            .map(|artifact| artifact.artifact_id.as_str())
            .collect();
        assert_eq!(shipped_ids, vec!["artifact-b", "artifact-c"]);

        match bridge.runtime() {
            FederationBridgeRuntime::EdgeReplay(runtime) => {
                assert_eq!(runtime.retained_artifacts.len(), 2);
                assert_eq!(runtime.shipped_batches, 1);
            }
            other => panic!("expected edge replay runtime, got {other:?}"),
        }
    }

    // -- Distributed supervision compiler -----------------------------------

    #[test]
    fn distributed_supervision_rejects_duplicate_node_ids() {
        let alpha_orders = distributed_node("alpha", "orders", "zone-a");
        let alpha_payments = distributed_node("alpha", "payments", "zone-b");

        let err = DistributedSupervisionCompiler::compile(&[alpha_orders, alpha_payments])
            .expect_err("duplicate node ids must be rejected");

        assert_eq!(
            err,
            FederationError::DuplicateDistributedSupervisionNode {
                node_id: "alpha".to_owned(),
            }
        );
    }

    #[test]
    fn distributed_supervision_rejects_unknown_monitor_target() {
        let alpha =
            distributed_node("alpha", "orders", "zone-a").with_monitor_targets(["missing-node"]);

        let err = DistributedSupervisionCompiler::compile(&[alpha])
            .expect_err("unknown monitor targets must be rejected");

        assert_eq!(
            err,
            FederationError::UnknownDistributedSupervisionTarget {
                node_id: "alpha".to_owned(),
                target: "missing-node".to_owned(),
                relation: "monitor",
            }
        );
    }

    #[test]
    fn distributed_supervision_rejects_same_domain_failover() {
        let alpha = distributed_node("alpha", "orders", "zone-a").with_failover_targets(["beta"]);
        let beta = distributed_node("beta", "billing", "zone-a");

        let err = DistributedSupervisionCompiler::compile(&[alpha, beta])
            .expect_err("failover must cross failure domains");

        assert_eq!(
            err,
            FederationError::FailoverTargetSameFailureDomain {
                node_id: "alpha".to_owned(),
                target: "beta".to_owned(),
                failure_domain: "zone-a".to_owned(),
            }
        );
    }

    #[test]
    fn distributed_supervision_compiles_mailbox_monitor_link_lease_and_evidence_plans() {
        let alpha = distributed_node("alpha", "orders", "zone-a")
            .with_export_morphisms(vec![rename_mailbox_prefix("orders", "fabric-egress")])
            .with_monitor_targets(["beta"])
            .with_link_targets(["beta"])
            .with_failover_targets(["beta"]);
        let beta = distributed_node("beta", "billing", "zone-b")
            .with_link_targets(["alpha"])
            .with_import_morphisms(vec![rename_mailbox_prefix("billing", "fabric-ingress")]);

        let plan = DistributedSupervisionCompiler::compile(&[alpha, beta])
            .expect("distributed supervision plan should compile");

        assert_eq!(plan.nodes.len(), 2);
        assert_eq!(plan.mailbox_routes.len(), 2);
        assert_eq!(plan.monitor_plans.len(), 1);
        assert_eq!(plan.link_plans.len(), 1);
        assert_eq!(plan.registry_leases.len(), 2);
        assert_eq!(plan.failover_handoffs.len(), 1);
        assert_eq!(plan.evidence_hooks.len(), 2);

        let alpha_node = plan
            .nodes
            .iter()
            .find(|node| node.node_id.as_str() == "alpha")
            .expect("alpha node should exist");
        assert_eq!(
            alpha_node.mailbox_subject.as_str(),
            "tenant.acme.service.orders.mailbox.alpha"
        );
        assert_eq!(
            alpha_node.exported_mailbox_subject.as_str(),
            "tenant.acme.service.orders.fabric-egress.alpha"
        );
        assert!(matches!(
            &alpha_node.supervision_strategy,
            SupervisionStrategy::Restart(config)
                if config.max_restarts == 3 && config.window == Duration::from_secs(45)
        ));

        let beta_route = plan
            .mailbox_routes
            .iter()
            .find(|route| route.node_id.as_str() == "beta")
            .expect("beta route should exist");
        assert_eq!(
            beta_route.imported_mailbox_subject.as_str(),
            "tenant.acme.service.billing.fabric-ingress.beta"
        );

        let monitor = &plan.monitor_plans[0];
        assert_eq!(monitor.watcher.as_str(), "alpha");
        assert_eq!(monitor.monitored.as_str(), "beta");
        assert_eq!(
            monitor.notification_subject.as_str(),
            "$SYS.FABRIC.DRAIN.monitor.alpha.beta"
        );
        assert_eq!(
            monitor.monitored_mailbox_subject.as_str(),
            "tenant.acme.service.billing.mailbox.beta"
        );

        let link = &plan.link_plans[0];
        assert_eq!(link.left_node.as_str(), "alpha");
        assert_eq!(link.right_node.as_str(), "beta");
        assert_eq!(
            link.control_subject.as_str(),
            "$SYS.FABRIC.DRAIN.link.alpha.beta"
        );
        assert_eq!(link.family, SystemSubjectFamily::Drain);

        let alpha_lease = plan
            .registry_leases
            .iter()
            .find(|lease| lease.node_id.as_str() == "alpha")
            .expect("alpha lease should exist");
        assert_eq!(
            alpha_lease.registry_subject.as_str(),
            "tenant.acme.service.orders.discover"
        );
        assert_eq!(
            alpha_lease.lease_subject.as_str(),
            "$SYS.FABRIC.ROUTE.registry-lease.alpha"
        );
        assert_eq!(alpha_lease.lease_ttl, Duration::from_secs(45));

        let failover = &plan.failover_handoffs[0];
        assert_eq!(failover.source_node.as_str(), "alpha");
        assert_eq!(failover.target_node.as_str(), "beta");
        assert_eq!(failover.source_failure_domain, "zone-a");
        assert_eq!(failover.target_failure_domain, "zone-b");
        assert_eq!(
            failover.handoff_subject.as_str(),
            "$SYS.FABRIC.DRAIN.handoff.alpha.beta"
        );
        assert_eq!(
            failover.drain_subject.as_str(),
            "$SYS.FABRIC.DRAIN.failover.alpha.beta"
        );
        assert_eq!(
            failover.registry_lease_subject.as_str(),
            "$SYS.FABRIC.ROUTE.registry-lease.beta"
        );
        assert_eq!(
            failover.evidence_subject.as_str(),
            "$SYS.FABRIC.REPLAY.failover.alpha.beta"
        );
        assert!(matches!(
            &failover.target_strategy,
            SupervisionStrategy::Restart(_)
        ));

        let alpha_hook = plan
            .evidence_hooks
            .iter()
            .find(|hook| hook.node_id.as_str() == "alpha")
            .expect("alpha evidence hook should exist");
        assert_eq!(
            alpha_hook.observability_subject.as_str(),
            "tenant.acme.service.orders.telemetry.supervision-alpha"
        );
        assert_eq!(
            alpha_hook.replay_subject.as_str(),
            "$SYS.FABRIC.REPLAY.supervision.alpha"
        );
        assert_eq!(alpha_hook.family, SystemSubjectFamily::Replay);
    }

    #[test]
    fn distributed_supervision_deduplicates_bidirectional_links() {
        let alpha = distributed_node("alpha", "orders", "zone-a").with_link_targets(["beta"]);
        let beta = distributed_node("beta", "billing", "zone-b").with_link_targets(["alpha"]);

        let plan =
            DistributedSupervisionCompiler::compile(&[alpha, beta]).expect("links should compile");

        assert_eq!(plan.link_plans.len(), 1);
        assert_eq!(
            plan.link_plans[0].control_subject.as_str(),
            "$SYS.FABRIC.DRAIN.link.alpha.beta"
        );
    }

    // -- Default enum values -------------------------------------------------

    #[test]
    fn default_enum_values_are_expected() {
        assert_eq!(
            InterestPropagationPolicy::default(),
            InterestPropagationPolicy::DemandDriven
        );
        assert_eq!(OrderingGuarantee::default(), OrderingGuarantee::PerSubject);
        assert_eq!(CatchUpPolicy::default(), CatchUpPolicy::SnapshotThenDelta);
        assert_eq!(
            EvidenceShippingPolicy::default(),
            EvidenceShippingPolicy::OnReconnect
        );
        assert_eq!(
            FederationBridgeState::default(),
            FederationBridgeState::Provisioning
        );
    }
