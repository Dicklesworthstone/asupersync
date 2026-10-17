    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn delivery_class_default_is_ephemeral_interactive() {
        assert_eq!(
            DeliveryClass::default(),
            DeliveryClass::EphemeralInteractive
        );
    }

    #[test]
    fn delivery_class_order_tracks_non_decreasing_cost() {
        for pair in DeliveryClass::ALL.windows(2) {
            let left = pair[0].cost_vector();
            let right = pair[1].cost_vector();
            assert!(
                left <= right,
                "expected {:?} cost {:?} <= {:?} cost {:?}",
                pair[0],
                left,
                pair[1],
                right
            );
        }
    }

    #[test]
    fn delivery_class_minimum_ack_is_monotonic() {
        for pair in DeliveryClass::ALL.windows(2) {
            assert!(
                pair[0].minimum_ack() <= pair[1].minimum_ack(),
                "expected {:?} minimum ack {} <= {:?} minimum ack {}",
                pair[0],
                pair[0].minimum_ack(),
                pair[1],
                pair[1].minimum_ack()
            );
        }
    }

    #[test]
    fn ack_kind_order_is_progressive() {
        assert!(AckKind::Accepted < AckKind::Committed);
        assert!(AckKind::Committed < AckKind::Recoverable);
        assert!(AckKind::Recoverable < AckKind::Served);
        assert!(AckKind::Served < AckKind::Received);
    }

    #[test]
    fn serde_round_trip_preserves_taxonomy_values() {
        let class = DeliveryClass::MobilitySafe;
        let ack = AckKind::Recoverable;

        let class_json = serde_json::to_string(&class).expect("serialize delivery class");
        let ack_json = serde_json::to_string(&ack).expect("serialize ack kind");

        assert_eq!(
            serde_json::from_str::<DeliveryClass>(&class_json).expect("deserialize delivery class"),
            class
        );
        assert_eq!(
            serde_json::from_str::<AckKind>(&ack_json).expect("deserialize ack kind"),
            ack
        );
    }

    #[test]
    fn provider_policy_requires_non_empty_admissible_set() {
        let err = DeliveryClassPolicy::new(DeliveryClass::EphemeralInteractive, [])
            .expect_err("empty provider policy must fail");
        assert_eq!(err, DeliveryClassPolicyError::EmptyProviderPolicy);
    }

    #[test]
    fn provider_policy_requires_default_to_be_admissible() {
        let err = DeliveryClassPolicy::new(
            DeliveryClass::DurableOrdered,
            [DeliveryClass::EphemeralInteractive],
        )
        .expect_err("default outside admissible set must fail");
        assert_eq!(
            err,
            DeliveryClassPolicyError::DefaultClassNotAdmissible {
                default_class: DeliveryClass::DurableOrdered,
            }
        );
    }

    #[test]
    fn provider_policy_deduplicates_and_sorts_classes() {
        let policy = DeliveryClassPolicy::new(
            DeliveryClass::DurableOrdered,
            [
                DeliveryClass::DurableOrdered,
                DeliveryClass::EphemeralInteractive,
                DeliveryClass::DurableOrdered,
            ],
        )
        .expect("provider policy should canonicalize duplicates");

        assert_eq!(
            policy.admissible_classes(),
            &[
                DeliveryClass::EphemeralInteractive,
                DeliveryClass::DurableOrdered,
            ]
        );
    }

    #[test]
    fn provider_policy_selection_is_invariant_under_duplicate_permutation() {
        let canonical = DeliveryClassPolicy::new(
            DeliveryClass::ObligationBacked,
            [
                DeliveryClass::DurableOrdered,
                DeliveryClass::ObligationBacked,
                DeliveryClass::MobilitySafe,
            ],
        )
        .expect("canonical policy");
        let permuted_with_duplicates = DeliveryClassPolicy::new(
            DeliveryClass::ObligationBacked,
            [
                DeliveryClass::MobilitySafe,
                DeliveryClass::ObligationBacked,
                DeliveryClass::DurableOrdered,
                DeliveryClass::MobilitySafe,
                DeliveryClass::DurableOrdered,
            ],
        )
        .expect("permuted policy");

        assert_eq!(permuted_with_duplicates, canonical);
        for requested in [
            None,
            Some(DeliveryClass::DurableOrdered),
            Some(DeliveryClass::ObligationBacked),
            Some(DeliveryClass::MobilitySafe),
            Some(DeliveryClass::EphemeralInteractive),
            Some(DeliveryClass::ForensicReplayable),
        ] {
            assert_eq!(
                permuted_with_duplicates.select_for_caller(requested),
                canonical.select_for_caller(requested),
                "caller selection changed for request {requested:?}"
            );
        }
    }

    #[test]
    fn provider_policy_uses_default_when_caller_omits_request() {
        let policy = DeliveryClassPolicy::new(
            DeliveryClass::DurableOrdered,
            [
                DeliveryClass::EphemeralInteractive,
                DeliveryClass::DurableOrdered,
            ],
        )
        .expect("valid provider policy");

        assert_eq!(
            policy
                .select_for_caller(None)
                .expect("use provider default"),
            DeliveryClass::DurableOrdered
        );
    }

    #[test]
    fn provider_policy_rejects_unavailable_requested_class() {
        let policy = DeliveryClassPolicy::new(
            DeliveryClass::EphemeralInteractive,
            [DeliveryClass::EphemeralInteractive],
        )
        .expect("valid provider policy");

        let err = policy
            .select_for_caller(Some(DeliveryClass::ForensicReplayable))
            .expect_err("caller request outside provider envelope must fail");
        assert_eq!(
            err,
            DeliveryClassPolicyError::RequestedClassNotAdmissible {
                requested: DeliveryClass::ForensicReplayable,
                default_class: DeliveryClass::EphemeralInteractive,
            }
        );
    }

    #[test]
    fn provider_policy_deserialization_revalidates_invariants() {
        let invalid =
            r#"{"default_class":"durable_ordered","admissible_classes":["ephemeral_interactive"]}"#;
        let err = serde_json::from_str::<DeliveryClassPolicy>(invalid)
            .expect_err("invalid serialized policy must be rejected");
        let err = err.to_string();
        assert!(
            err.contains("default class durable-ordered"),
            "expected validation error to mention the invalid default, got {err}"
        );
    }

    #[test]
    fn delivery_class_display_and_minimum_ack_cover_every_variant() {
        let cases = [
            (
                DeliveryClass::EphemeralInteractive,
                "ephemeral-interactive",
                AckKind::Accepted,
            ),
            (
                DeliveryClass::DurableOrdered,
                "durable-ordered",
                AckKind::Recoverable,
            ),
            (
                DeliveryClass::ObligationBacked,
                "obligation-backed",
                AckKind::Served,
            ),
            (
                DeliveryClass::MobilitySafe,
                "mobility-safe",
                AckKind::Received,
            ),
            (
                DeliveryClass::ForensicReplayable,
                "forensic-replayable",
                AckKind::Received,
            ),
        ];

        for (class, expected_display, expected_ack) in cases {
            assert_eq!(class.to_string(), expected_display);
            assert_eq!(class.minimum_ack(), expected_ack);
        }
    }

    #[test]
    fn provider_policy_allows_valid_requested_classes_and_round_trips() {
        let policy = DeliveryClassPolicy::new(
            DeliveryClass::DurableOrdered,
            [
                DeliveryClass::MobilitySafe,
                DeliveryClass::DurableOrdered,
                DeliveryClass::ObligationBacked,
            ],
        )
        .expect("valid provider policy");

        assert!(policy.allows(DeliveryClass::DurableOrdered));
        assert!(policy.allows(DeliveryClass::ObligationBacked));
        assert!(policy.allows(DeliveryClass::MobilitySafe));
        assert!(!policy.allows(DeliveryClass::ForensicReplayable));

        assert_eq!(
            policy
                .select_for_caller(Some(DeliveryClass::ObligationBacked))
                .expect("caller request within provider envelope"),
            DeliveryClass::ObligationBacked
        );
        assert_eq!(
            policy
                .select_for_caller(Some(DeliveryClass::MobilitySafe))
                .expect("caller request within provider envelope"),
            DeliveryClass::MobilitySafe
        );

        let json = serde_json::to_string(&policy).expect("serialize provider policy");
        let decoded: DeliveryClassPolicy =
            serde_json::from_str(&json).expect("deserialize provider policy");
        assert_eq!(decoded, policy);
        assert_eq!(
            decoded.admissible_classes(),
            &[
                DeliveryClass::DurableOrdered,
                DeliveryClass::ObligationBacked,
                DeliveryClass::MobilitySafe,
            ]
        );
    }
