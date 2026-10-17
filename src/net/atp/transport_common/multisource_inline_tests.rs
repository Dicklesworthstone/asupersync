    use super::*;

    fn object_ref() -> MultiSourceObjectRef {
        MultiSourceObjectRef::new("object-01", "abc123")
    }

    fn auth(key_id: &str) -> MultiSourceAuth {
        MultiSourceAuth::SymbolAuth {
            key_id: key_id.to_string(),
        }
    }

    fn peer(id: &str, endpoint: &str, priority: u32) -> MultiSourcePeer {
        MultiSourcePeer::new(id, endpoint, priority, auth("key-a"))
    }

    #[test]
    fn production_default_requires_two_authenticated_sources() {
        assert_eq!(
            MultiSourceSelectionConfig::production_default(),
            MultiSourceSelectionConfig {
                min_sources: 2,
                max_sources: 4,
                allow_unauthenticated_lab: false,
            }
        );
    }

    #[test]
    fn selection_is_priority_then_peer_then_endpoint_deterministic() {
        let plan = plan_multi_source_fetch(
            object_ref(),
            [
                peer("peer-c", "10.0.0.3:8472", 10),
                peer("peer-b", "10.0.0.2:8472", 5),
                peer("peer-a", "10.0.0.1:8472", 5),
            ],
            MultiSourceSelectionConfig {
                min_sources: 2,
                max_sources: 2,
                allow_unauthenticated_lab: false,
            },
        )
        .unwrap();

        assert_eq!(plan.source_count(), 2);
        assert_eq!(plan.selected_sources[0].peer.peer_id, "peer-a");
        assert_eq!(plan.selected_sources[1].peer.peer_id, "peer-b");
        assert_eq!(
            plan.selected_sources
                .iter()
                .map(|source| source.selection_order)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
    }

    #[test]
    fn selected_sources_get_complementary_symbol_biases() {
        let plan = plan_multi_source_fetch(
            object_ref(),
            [
                peer("peer-a", "10.0.0.1:8472", 1),
                peer("peer-b", "10.0.0.2:8472", 2),
                peer("peer-c", "10.0.0.3:8472", 3),
            ],
            MultiSourceSelectionConfig {
                min_sources: 2,
                max_sources: 3,
                allow_unauthenticated_lab: false,
            },
        )
        .unwrap();

        assert_eq!(
            plan.selected_sources
                .iter()
                .map(|source| source.symbol_bias)
                .collect::<Vec<_>>(),
            vec![
                MultiSourceSymbolBias::SourceFirst,
                MultiSourceSymbolBias::RepairFirst,
                MultiSourceSymbolBias::Balanced,
            ]
        );
        assert_eq!(
            plan.selected_sources[0].symbol_bias.bias_id(),
            "source_first"
        );
    }

    #[test]
    fn stop_commands_cover_every_selected_source_in_selection_order() {
        let plan = plan_multi_source_fetch(
            object_ref(),
            [
                peer("peer-b", "10.0.0.2:8472", 1),
                peer("peer-a", "10.0.0.1:8472", 0),
            ],
            MultiSourceSelectionConfig::production_default(),
        )
        .unwrap();

        let stops = plan.stop_commands(MultiSourceStopReason::DecodedAndVerified);
        assert_eq!(stops.len(), 2);
        assert_eq!(stops[0].peer_id, "peer-a");
        assert_eq!(stops[1].peer_id, "peer-b");
        assert!(stops.iter().all(|stop| {
            stop.object_id == "object-01" && stop.reason.reason_id() == "decoded_and_verified"
        }));
    }

    #[test]
    fn unauthenticated_sources_fail_closed_outside_lab_mode() {
        let err = plan_multi_source_fetch(
            object_ref(),
            [
                peer("peer-a", "10.0.0.1:8472", 0),
                MultiSourcePeer::new(
                    "peer-b",
                    "10.0.0.2:8472",
                    1,
                    MultiSourceAuth::UnauthenticatedLab,
                ),
            ],
            MultiSourceSelectionConfig::production_default(),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            MultiSourcePlanError::UnauthenticatedPeerRejected { peer_id }
                if peer_id == "peer-b"
        ));
    }

    #[test]
    fn lab_mode_must_still_meet_minimum_source_count() {
        let plan = plan_multi_source_fetch(
            object_ref(),
            [
                MultiSourcePeer::new(
                    "peer-a",
                    "10.0.0.1:8472",
                    0,
                    MultiSourceAuth::UnauthenticatedLab,
                ),
                MultiSourcePeer::new(
                    "peer-b",
                    "10.0.0.2:8472",
                    1,
                    MultiSourceAuth::UnauthenticatedLab,
                ),
            ],
            MultiSourceSelectionConfig {
                min_sources: 2,
                max_sources: 2,
                allow_unauthenticated_lab: true,
            },
        )
        .unwrap();

        assert_eq!(plan.source_count(), 2);
        assert_eq!(
            plan.selected_sources[0].peer.auth.mode_id(),
            "unauthenticated_lab"
        );
    }

    #[test]
    fn duplicate_peer_ids_and_endpoints_fail_closed() {
        assert!(matches!(
            plan_multi_source_fetch(
                object_ref(),
                [
                    peer("peer-a", "10.0.0.1:8472", 0),
                    peer("peer-a", "10.0.0.2:8472", 1),
                ],
                MultiSourceSelectionConfig::production_default(),
            ),
            Err(MultiSourcePlanError::DuplicatePeerId { .. })
        ));

        assert!(matches!(
            plan_multi_source_fetch(
                object_ref(),
                [
                    peer("peer-a", "10.0.0.1:8472", 0),
                    peer("peer-b", "10.0.0.1:8472", 1),
                ],
                MultiSourceSelectionConfig::production_default(),
            ),
            Err(MultiSourcePlanError::DuplicateEndpoint { .. })
        ));
    }

    #[test]
    fn invalid_config_and_object_identity_fail_closed() {
        assert!(matches!(
            plan_multi_source_fetch(
                MultiSourceObjectRef::new("", "abc"),
                [peer("peer-a", "10.0.0.1:8472", 0)],
                MultiSourceSelectionConfig::production_default(),
            ),
            Err(MultiSourcePlanError::EmptyObjectId)
        ));
        assert!(matches!(
            plan_multi_source_fetch(
                object_ref(),
                [
                    peer("peer-a", "10.0.0.1:8472", 0),
                    peer("peer-b", "10.0.0.2:8472", 1),
                ],
                MultiSourceSelectionConfig {
                    min_sources: 3,
                    max_sources: 2,
                    allow_unauthenticated_lab: false,
                },
            ),
            Err(MultiSourcePlanError::MaxSourcesBelowMin { .. })
        ));
    }
