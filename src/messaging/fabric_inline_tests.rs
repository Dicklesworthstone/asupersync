    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::super::ir::ReplySpaceRule;
    use super::super::service::{
        CompensationSemantics, EvidenceLevel, MobilityConstraint, OverloadPolicy, ServiceAdmission,
        ValidatedServiceRequest,
    };
    use super::*;
    use crate::runtime::RuntimeBuilder;
    use crate::test_utils::run_test_with_cx;
    use proptest::prelude::*;
    use std::collections::BTreeSet;
    #[cfg(debug_assertions)]
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::time::Duration;

    fn candidate(
        name: &str,
        domain: &str,
        storage_class: StorageClass,
        latency_millis: u32,
    ) -> StewardCandidate {
        StewardCandidate::new(NodeId::new(name), domain)
            .with_role(NodeRole::Steward)
            .with_role(NodeRole::RepairWitness)
            .with_storage_class(storage_class)
            .with_latency_millis(latency_millis)
    }

    fn service_admission(
        request_id: &str,
        subject: &str,
        delivery_class: DeliveryClass,
        timeout: Option<Duration>,
        issued_at: crate::types::Time,
    ) -> ServiceAdmission {
        let validated = ValidatedServiceRequest {
            delivery_class,
            timeout,
            priority_hint: None,
            guaranteed_durability: delivery_class,
            evidence_level: EvidenceLevel::Standard,
            mobility_constraint: MobilityConstraint::Unrestricted,
            compensation_policy: CompensationSemantics::None,
            overload_policy: OverloadPolicy::RejectNew,
        };
        let certificate = RequestCertificate::from_validated(
            request_id.to_owned(),
            "caller-a".to_owned(),
            subject.to_owned(),
            &validated,
            ReplySpaceRule::CallerInbox,
            "OrderService".to_owned(),
            0xC0DE,
            issued_at,
        );

        ServiceAdmission {
            validated,
            certificate,
        }
    }

    fn grant_capability(cx: &Cx, capability: FabricCapability) {
        cx.grant_fabric_capability(capability)
            .expect("fabric capability grant");
    }

    fn grant_publish(cx: &Cx, subject: &str) {
        grant_capability(
            cx,
            FabricCapability::Publish {
                subject: SubjectPattern::parse(subject).expect("publish subject"),
            },
        );
    }

    fn grant_subscribe(cx: &Cx, subject: &str) {
        grant_capability(
            cx,
            FabricCapability::Subscribe {
                subject: SubjectPattern::parse(subject).expect("subscribe subject"),
            },
        );
    }

    fn grant_create_stream(cx: &Cx, subject: &str) {
        grant_capability(
            cx,
            FabricCapability::CreateStream {
                subject: SubjectPattern::parse(subject).expect("stream subject"),
            },
        );
    }

    fn canonical_cell_key(subject: &str) -> String {
        PlacementPolicy::default()
            .normalization
            .normalize(&SubjectPattern::parse(subject).expect("subject pattern"))
            .expect("canonical subject partition")
            .canonical_key()
    }

    #[test]
    fn stream_config_defaults_to_ephemeral_interactive() {
        let config = FabricStreamConfig::default();
        assert_eq!(config.delivery_class, DeliveryClass::EphemeralInteractive);
        assert_eq!(config.capture_policy, CapturePolicy::ExplicitOptIn);
        assert!(config.subjects.is_empty());
    }

    #[test]
    fn stream_config_rejects_empty_subject_lists() {
        let err = FabricStreamConfig::default()
            .validate()
            .expect_err("empty stream declarations must fail closed");
        assert_eq!(err.kind(), ErrorKind::ConfigError);
    }

    #[test]
    fn stream_config_rejects_overlapping_subjects() {
        let config = FabricStreamConfig {
            subjects: vec![
                SubjectPattern::parse("orders.>").expect("orders wildcard"),
                SubjectPattern::parse("orders.created").expect("orders literal"),
            ],
            ..FabricStreamConfig::default()
        };

        let err = config
            .validate()
            .expect_err("overlapping capture declarations must be rejected");
        assert_eq!(err.kind(), ErrorKind::User);
    }

    #[test]
    fn connect_rejects_blank_endpoints() {
        run_test_with_cx(|cx| async move {
            let err = Fabric::connect(&cx, "   ")
                .await
                .expect_err("blank endpoint must fail");
            assert_eq!(err.kind(), ErrorKind::ConfigError);
        });
    }

    #[test]
    fn publish_and_subscribe_round_trip_with_ephemeral_defaults() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            grant_subscribe(&cx, "orders.>");
            let fabric = Fabric::connect(&cx, "node1:4222/publish")
                .await
                .expect("connect");
            let mut subscription = fabric.subscribe(&cx, "orders.>").await.expect("subscribe");

            let receipt = fabric
                .publish(&cx, "orders.created", b"payload".to_vec())
                .await
                .expect("publish");
            let message = subscription.next(&cx).await.expect("message");

            assert_eq!(receipt.ack_kind, AckKind::Accepted);
            assert_eq!(receipt.delivery_class, DeliveryClass::EphemeralInteractive);
            assert_eq!(message.delivery_class, DeliveryClass::EphemeralInteractive);
            assert_eq!(message.subject.as_str(), "orders.created");
            assert_eq!(message.payload, b"payload".to_vec());
        });
    }

    #[test]
    fn request_uses_same_surface_and_returns_reply() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "service.lookup");
            grant_subscribe(&cx, "service.lookup");
            let fabric = Fabric::connect(&cx, "node1:4222/request")
                .await
                .expect("connect");
            let reply = fabric
                .request(&cx, "service.lookup", b"lookup".to_vec())
                .await
                .expect("request");

            assert_eq!(reply.ack_kind, AckKind::Accepted);
            assert_eq!(reply.delivery_class, DeliveryClass::EphemeralInteractive);
            assert_eq!(reply.subject.as_str(), "service.lookup");
            assert_eq!(reply.payload, b"lookup".to_vec());
        });
    }

    #[test]
    fn certified_request_emits_certificates_and_resolves_obligations() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "service.lookup");
            grant_subscribe(&cx, "service.>");
            let fabric = Fabric::connect(&cx, "node1:4222/certified")
                .await
                .expect("connect");
            let mut subscription = fabric.subscribe(&cx, "service.>").await.expect("subscribe");
            let mut ledger = ObligationLedger::new();
            let admission = service_admission(
                "req-certified",
                "service.lookup",
                DeliveryClass::ObligationBacked,
                Some(Duration::from_secs(5)),
                cx.now(),
            );

            let certified = fabric
                .request_certified(
                    &cx,
                    &mut ledger,
                    &admission,
                    "callee-a",
                    b"lookup".to_vec(),
                    AckKind::Received,
                    true,
                )
                .await
                .expect("certified request");
            let published = subscription.next(&cx).await.expect("published message");

            assert_eq!(published.delivery_class, DeliveryClass::ObligationBacked);
            assert_eq!(certified.reply.ack_kind, AckKind::Received);
            assert_eq!(
                certified.reply.delivery_class,
                DeliveryClass::ObligationBacked
            );
            assert_eq!(certified.reply.subject.as_str(), "service.lookup");
            assert_eq!(certified.reply.payload, b"lookup".to_vec());
            assert!(certified.request_certificate.validate().is_ok());
            assert!(certified.reply_certificate.validate().is_ok());
            assert_eq!(
                certified.reply_certificate.delivery_class,
                DeliveryClass::ObligationBacked
            );
            assert!(certified.reply_certificate.service_obligation_id.is_some());
            assert_eq!(
                certified.reply_certificate.service_latency,
                Duration::from_nanos(
                    certified
                        .reply_certificate
                        .issued_at
                        .duration_since(admission.certificate.issued_at)
                )
            );
            assert_eq!(
                certified
                    .delivery_receipt
                    .as_ref()
                    .map(|receipt| receipt.delivery_boundary),
                Some(AckKind::Received)
            );
            assert_eq!(ledger.pending_count(), 0);
            assert!(ledger.check_leaks().is_clean());
        });
    }

    #[test]
    fn certified_request_rejects_non_obligation_delivery_classes() {
        run_test_with_cx(|cx| async move {
            let fabric = Fabric::connect(&cx, "node1:4222/certified-reject")
                .await
                .expect("connect");
            let mut ledger = ObligationLedger::new();
            let admission = service_admission(
                "req-ephemeral",
                "service.lookup",
                DeliveryClass::EphemeralInteractive,
                None,
                cx.now(),
            );

            let err = fabric
                .request_certified(
                    &cx,
                    &mut ledger,
                    &admission,
                    "callee-a",
                    b"lookup".to_vec(),
                    AckKind::Accepted,
                    false,
                )
                .await
                .expect_err("ephemeral class must use plain request");

            assert_eq!(err.kind(), ErrorKind::User);
            assert!(
                err.to_string().contains("obligation-backed or stronger"),
                "unexpected error: {err}"
            );
            assert!(ledger.is_empty());
        });
    }

    #[test]
    fn stream_accepts_explicit_subjects_and_preserves_endpoint() {
        run_test_with_cx(|cx| async move {
            grant_create_stream(&cx, "orders.>");
            let fabric = Fabric::connect(&cx, "node1:4222/stream")
                .await
                .expect("connect");
            let handle = fabric
                .stream(
                    &cx,
                    FabricStreamConfig {
                        subjects: vec![SubjectPattern::parse("orders.>").expect("pattern")],
                        delivery_class: DeliveryClass::DurableOrdered,
                        capture_policy: CapturePolicy::ExplicitOptIn,
                        request_timeout: Some(Duration::from_secs(5)),
                    },
                )
                .await
                .expect("stream");

            assert_eq!(handle.endpoint(), "node1:4222/stream");
            assert_eq!(
                handle.config().delivery_class,
                DeliveryClass::DurableOrdered
            );
            assert_eq!(handle.config().subjects.len(), 1);
        });
    }

    #[test]
    fn stream_requires_create_stream_capability() {
        run_test_with_cx(|cx| async move {
            let fabric = Fabric::connect(&cx, "node1:4222/stream-denied")
                .await
                .expect("connect");

            let err = fabric
                .stream(
                    &cx,
                    FabricStreamConfig {
                        subjects: vec![SubjectPattern::parse("orders.>").expect("pattern")],
                        delivery_class: DeliveryClass::DurableOrdered,
                        capture_policy: CapturePolicy::ExplicitOptIn,
                        request_timeout: Some(Duration::from_secs(5)),
                    },
                )
                .await
                .expect_err("stream declaration without create-stream capability must fail");

            assert_eq!(err.kind(), ErrorKind::AdmissionDenied);
            let decisions = fabric
                .decision_records()
                .into_iter()
                .filter(|record| record.contract_name() == "fabric_capability_decision")
                .collect::<Vec<_>>();
            assert_eq!(decisions.len(), 1);
            assert_eq!(decisions[0].audit.action_chosen, "reject");
        });
    }

    #[test]
    fn stream_requires_capability_for_each_declared_subject() {
        run_test_with_cx(|cx| async move {
            grant_create_stream(&cx, "orders.created");
            let fabric = Fabric::connect(&cx, "node1:4222/stream-partial")
                .await
                .expect("connect");

            let err = fabric
                .stream(
                    &cx,
                    FabricStreamConfig {
                        subjects: vec![
                            SubjectPattern::parse("orders.created").expect("created"),
                            SubjectPattern::parse("orders.snapshot").expect("snapshot"),
                        ],
                        delivery_class: DeliveryClass::DurableOrdered,
                        capture_policy: CapturePolicy::ExplicitOptIn,
                        request_timeout: Some(Duration::from_secs(5)),
                    },
                )
                .await
                .expect_err("partially authorized stream declarations must fail closed");

            assert_eq!(err.kind(), ErrorKind::AdmissionDenied);
            let decisions = fabric
                .decision_records()
                .into_iter()
                .filter(|record| record.contract_name() == "fabric_capability_decision")
                .collect::<Vec<_>>();
            assert_eq!(decisions.len(), 2);
            assert_eq!(decisions[0].audit.action_chosen, "allow");
            assert_eq!(decisions[1].audit.action_chosen, "reject");
        });
    }

    #[test]
    fn same_endpoint_connections_share_published_messages() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            grant_subscribe(&cx, "orders.>");
            let publisher = Fabric::connect(&cx, "node1:4222/shared")
                .await
                .expect("connect");
            let subscriber = Fabric::connect(&cx, "node1:4222/shared")
                .await
                .expect("connect");
            let mut subscription = subscriber
                .subscribe(&cx, "orders.>")
                .await
                .expect("subscribe");

            publisher
                .publish(&cx, "orders.created", b"payload".to_vec())
                .await
                .expect("publish");
            let message = subscription.next(&cx).await.expect("message");

            assert_eq!(message.subject.as_str(), "orders.created");
            assert_eq!(message.payload, b"payload".to_vec());
        });
    }

    #[test]
    fn different_endpoints_do_not_share_messages() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            grant_subscribe(&cx, "orders.>");
            let left = Fabric::connect(&cx, "node1:4222/left")
                .await
                .expect("connect");
            let right = Fabric::connect(&cx, "node1:4222/right")
                .await
                .expect("connect");
            let mut subscription = right.subscribe(&cx, "orders.>").await.expect("subscribe");

            left.publish(&cx, "orders.created", b"payload".to_vec())
                .await
                .expect("publish");

            assert_eq!(subscription.next(&cx).await, None);
        });
    }

    #[test]
    fn late_subscriber_does_not_replay_prior_messages_on_shared_endpoint() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            grant_subscribe(&cx, "orders.>");
            let publisher = Fabric::connect(&cx, "node1:4222/live-only")
                .await
                .expect("connect");
            let late_subscriber = Fabric::connect(&cx, "node1:4222/live-only")
                .await
                .expect("connect");

            publisher
                .publish(&cx, "orders.created", b"before-subscribe".to_vec())
                .await
                .expect("publish");

            let mut subscription = late_subscriber
                .subscribe(&cx, "orders.>")
                .await
                .expect("subscribe");

            assert_eq!(
                subscription.next(&cx).await,
                None,
                "late subscribers should not replay pre-subscription packet-plane history"
            );

            publisher
                .publish(&cx, "orders.created", b"after-subscribe".to_vec())
                .await
                .expect("publish");

            let message = subscription.next(&cx).await.expect("live message");
            assert_eq!(message.payload, b"after-subscribe".to_vec());
        });
    }

    #[test]
    fn publish_creates_subject_cells_and_prunes_after_delivery() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            grant_subscribe(&cx, "orders.created");
            let fabric = Fabric::connect(&cx, "node1:4222/cell-create")
                .await
                .expect("connect");
            let mut subscription = fabric
                .subscribe(&cx, "orders.created")
                .await
                .expect("subscribe");

            fabric
                .publish(&cx, "orders.created", b"payload".to_vec())
                .await
                .expect("publish");

            {
                let state = fabric.state.lock();
                let cell_key = canonical_cell_key("orders.created");
                let cell = state.cells.get(&cell_key).expect("cell runtime");
                assert_eq!(state.cells.len(), 1);
                assert_eq!(state.cell_routes.len(), 1);
                assert_eq!(cell.cell.subject_partition.canonical_key(), cell_key);
                assert_eq!(cell.buffer.len(), 1);
                assert_eq!(cell.state, FabricCellBufferState::Buffered);
            }

            let message = subscription.next(&cx).await.expect("message");
            assert_eq!(message.subject.as_str(), "orders.created");
            assert_eq!(message.payload, b"payload".to_vec());

            let state = fabric.state.lock();
            let cell = state
                .cells
                .get(&canonical_cell_key("orders.created"))
                .expect("cell runtime");
            assert!(cell.buffer.is_empty(), "consumed messages should be pruned");
            assert_eq!(cell.state, FabricCellBufferState::Empty);
        });
    }

    #[test]
    fn wildcard_subscription_reads_messages_across_multiple_cells_in_publish_order() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.>");
            grant_subscribe(&cx, "orders.>");
            let fabric = Fabric::connect(&cx, "node1:4222/fanout")
                .await
                .expect("connect");
            let mut subscription = fabric.subscribe(&cx, "orders.>").await.expect("subscribe");

            fabric
                .publish(&cx, "orders.created", b"created".to_vec())
                .await
                .expect("first publish");
            fabric
                .publish(&cx, "orders.updated", b"updated".to_vec())
                .await
                .expect("second publish");

            let first = subscription.next(&cx).await.expect("first message");
            let second = subscription.next(&cx).await.expect("second message");

            assert_eq!(first.subject.as_str(), "orders.created");
            assert_eq!(first.payload, b"created".to_vec());
            assert_eq!(second.subject.as_str(), "orders.updated");
            assert_eq!(second.payload, b"updated".to_vec());
            assert_eq!(subscription.next(&cx).await, None);

            let state = fabric.state.lock();
            assert_eq!(state.cells.len(), 2);
            assert!(
                state
                    .cells
                    .contains_key(&canonical_cell_key("orders.created"))
            );
            assert!(
                state
                    .cells
                    .contains_key(&canonical_cell_key("orders.updated"))
            );
        });
    }

    #[test]
    fn publish_backpressures_full_cells_until_subscribers_drain_them() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            grant_subscribe(&cx, "orders.created");
            let fabric = Fabric::connect(&cx, "node1:4222/backpressure")
                .await
                .expect("connect");
            fabric.state.lock().cell_buffer_capacity = 1;
            let mut subscription = fabric
                .subscribe(&cx, "orders.created")
                .await
                .expect("subscribe");

            fabric
                .publish(&cx, "orders.created", b"first".to_vec())
                .await
                .expect("first publish");

            let err = fabric
                .publish(&cx, "orders.created", b"second".to_vec())
                .await
                .expect_err("full cell should reject a second publish");
            assert_eq!(err.kind(), ErrorKind::ChannelFull);

            let cell_key = canonical_cell_key("orders.created");
            {
                let state = fabric.state.lock();
                let cell = state.cells.get(&cell_key).expect("cell runtime");
                assert_eq!(cell.state, FabricCellBufferState::Backpressured);
                assert_eq!(cell.buffer.len(), 1);
            }

            let drained = subscription.next(&cx).await.expect("drained message");
            assert_eq!(drained.payload, b"first".to_vec());

            fabric
                .publish(&cx, "orders.created", b"third".to_vec())
                .await
                .expect("drain should restore capacity");

            let delivered = subscription.next(&cx).await.expect("delivered message");
            assert_eq!(delivered.payload, b"third".to_vec());
        });
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        #[test]
        fn full_wildcard_subscription_preserves_publish_order_and_reuses_canonical_cells(
            subject_indexes in proptest::collection::vec(0usize..4, 1..8)
        ) {
            let endpoint = format!(
                "node1:4222/property-{:016x}",
                stable_hash(("fabric-property-order", &subject_indexes))
            );
            let runtime = RuntimeBuilder::current_thread()
                .build()
                .expect("failed to build runtime");
            let cx = Cx::for_testing();
            grant_publish(&cx, ">");
            grant_subscribe(&cx, ">");

            runtime.block_on(async move {
                let fabric = Fabric::connect(&cx, endpoint).await.expect("connect");
                let mut subscription = fabric.subscribe(&cx, ">").await.expect("subscribe");
                let subjects = [
                    "orders.created",
                    "orders.updated",
                    "_INBOX.orders.region.req-1",
                    "_INBOX.orders.region.req-2",
                ];

                for (ordinal, index) in subject_indexes.iter().copied().enumerate() {
                    fabric
                        .publish(&cx, subjects[index], vec![ordinal as u8])
                        .await
                        .expect("publish");
                }

                for (ordinal, index) in subject_indexes.iter().copied().enumerate() {
                    let message = subscription.next(&cx).await.expect("message");
                    assert_eq!(message.subject.as_str(), subjects[index]);
                    assert_eq!(message.payload, vec![ordinal as u8]);
                }
                assert_eq!(subscription.next(&cx).await, None);

                let expected_cells = subject_indexes
                    .iter()
                    .map(|index| canonical_cell_key(subjects[*index]))
                    .collect::<BTreeSet<_>>();
                let state = fabric.state.lock();
                let actual_cells = state.cells.keys().cloned().collect::<BTreeSet<_>>();
                assert_eq!(actual_cells, expected_cells);
            });
        }
    }

    #[test]
    fn parse_subject_pattern_trims_outer_whitespace() {
        let pattern = SubjectPattern::parse("  orders.created.>  ").expect("pattern");
        assert_eq!(pattern.canonical_key(), "orders.created.>");
    }

    #[test]
    fn parse_subject_pattern_rejects_non_terminal_tail_wildcard() {
        let err = SubjectPattern::parse("orders.>.created").expect_err("should reject");
        assert_eq!(err, SubjectPatternError::TailWildcardMustBeTerminal);
    }

    #[test]
    fn reply_space_aggregation_compacts_ephemeral_suffixes() {
        let pattern =
            SubjectPattern::parse("_INBOX.orders.region.instance.12345").expect("pattern");
        let compacted = pattern.aggregate_reply_space(ReplySpaceCompactionPolicy {
            enabled: true,
            preserve_segments: 3,
        });
        assert_eq!(compacted.canonical_key(), "_INBOX.orders.region.>");
    }

    #[test]
    fn overlap_detection_handles_literals_and_wildcards() {
        let left = SubjectPattern::parse("orders.*").expect("left");
        let right = SubjectPattern::parse("orders.created").expect("right");
        let third = SubjectPattern::parse("metrics.>").expect("third");
        let fourth = SubjectPattern::parse("orders.created").expect("fourth");

        assert!(left.overlaps(&right));
        assert!(!left.overlaps(&third));
        assert!(third.overlaps(&SubjectPattern::parse("metrics.region.1").expect("tail")));
        assert!(right.overlaps(&fourth));
    }

    #[test]
    fn tail_wildcard_requires_a_non_empty_suffix() {
        let wildcard = SubjectPattern::parse("orders.>").expect("wildcard");
        let bare_prefix = SubjectPattern::parse("orders").expect("bare prefix");

        assert!(!wildcard.overlaps(&bare_prefix));
        assert!(wildcard.overlaps(&SubjectPattern::parse("orders.created").expect("expanded")));
    }

    #[test]
    fn normalization_policy_applies_prefix_morphisms() {
        let policy = NormalizationPolicy {
            morphisms: vec![SubjectPrefixMorphism::new("svc.orders", "orders").expect("morphism")],
            reply_space_policy: ReplySpaceCompactionPolicy {
                enabled: true,
                preserve_segments: 3,
            },
        };

        let canonical = policy
            .normalize(&SubjectPattern::parse("svc.orders.created").expect("pattern"))
            .expect("normalized");

        assert_eq!(canonical.canonical_key(), "orders.created");
    }

    #[test]
    fn normalization_policy_chains_prefix_morphisms() {
        let policy = NormalizationPolicy {
            morphisms: vec![
                SubjectPrefixMorphism::new("svc.orders", "orders").expect("morphism"),
                SubjectPrefixMorphism::new("orders", "canonical.orders").expect("morphism"),
            ],
            reply_space_policy: ReplySpaceCompactionPolicy::default(),
        };

        let canonical = policy
            .normalize(&SubjectPattern::parse("svc.orders.created").expect("pattern"))
            .expect("normalized");

        assert_eq!(canonical.canonical_key(), "canonical.orders.created");
    }

    #[test]
    fn normalization_policy_rejects_morphism_cycles() {
        let policy = NormalizationPolicy {
            morphisms: vec![
                SubjectPrefixMorphism::new("svc.orders", "orders").expect("morphism"),
                SubjectPrefixMorphism::new("orders", "svc.orders").expect("morphism"),
            ],
            reply_space_policy: ReplySpaceCompactionPolicy::default(),
        };

        let err = policy
            .normalize(&SubjectPattern::parse("svc.orders.created").expect("pattern"))
            .expect_err("should reject cycle");

        assert!(matches!(err, FabricError::CyclicSubjectMorphisms { .. }));
    }

    #[test]
    fn normalization_policy_rejects_conflicting_morphisms() {
        let policy = NormalizationPolicy {
            morphisms: vec![
                SubjectPrefixMorphism::new("svc.orders", "orders").expect("left morphism"),
                SubjectPrefixMorphism::new("svc.orders", "legacy.orders").expect("right morphism"),
            ],
            reply_space_policy: ReplySpaceCompactionPolicy::default(),
        };

        let err = policy
            .normalize(&SubjectPattern::parse("svc.orders.created").expect("pattern"))
            .expect_err("conflicting rewrites must fail closed");

        assert!(matches!(
            err,
            FabricError::ConflictingSubjectMorphisms { .. }
        ));
    }

    #[test]
    fn normalization_policy_can_compact_reply_space_after_morphism() {
        let policy = NormalizationPolicy {
            morphisms: vec![SubjectPrefixMorphism::new("svc", "_INBOX").expect("morphism")],
            reply_space_policy: ReplySpaceCompactionPolicy {
                enabled: true,
                preserve_segments: 3,
            },
        };

        let canonical = policy
            .normalize(&SubjectPattern::parse("svc.orders.region.instance.123").expect("pattern"))
            .expect("normalized");

        assert_eq!(canonical.canonical_key(), "_INBOX.orders.region.>");
    }

    #[test]
    fn normalization_policy_canonicalize_partitions_deduplicates_aliases() {
        let policy = NormalizationPolicy {
            morphisms: vec![SubjectPrefixMorphism::new("svc.orders", "orders").expect("morphism")],
            reply_space_policy: ReplySpaceCompactionPolicy::default(),
        };
        let partitions = vec![
            SubjectPattern::parse("orders.created").expect("canonical"),
            SubjectPattern::parse("svc.orders.created").expect("alias"),
            SubjectPattern::parse("orders.created").expect("duplicate"),
        ];

        let canonical = policy
            .canonicalize_partitions(&partitions)
            .expect("canonical partitions");

        assert_eq!(canonical.len(), 1);
        assert_eq!(canonical[0].canonical_key(), "orders.created");
    }

    #[test]
    fn normalization_policy_canonicalize_partitions_preserves_nested_wildcards() {
        let policy = NormalizationPolicy {
            morphisms: vec![SubjectPrefixMorphism::new("svc", "canonical").expect("morphism")],
            reply_space_policy: ReplySpaceCompactionPolicy::default(),
        };
        let partitions = vec![
            SubjectPattern::parse("svc.region.*.>").expect("nested wildcard"),
            SubjectPattern::parse("svc.metrics.*").expect("disjoint wildcard"),
        ];

        let canonical = policy
            .canonicalize_partitions(&partitions)
            .expect("canonical partitions");
        let keys = canonical
            .into_iter()
            .map(|pattern| pattern.canonical_key())
            .collect::<Vec<_>>();

        assert_eq!(
            keys,
            vec![
                "canonical.metrics.*".to_string(),
                "canonical.region.*.>".to_string(),
            ]
        );
    }

    #[test]
    fn normalization_policy_canonicalize_partitions_rejects_overlap_after_normalization() {
        let policy = NormalizationPolicy {
            morphisms: vec![SubjectPrefixMorphism::new("svc.orders", "orders").expect("morphism")],
            reply_space_policy: ReplySpaceCompactionPolicy::default(),
        };
        let partitions = vec![
            SubjectPattern::parse("svc.orders.created").expect("alias"),
            SubjectPattern::parse("orders.*").expect("wildcard"),
        ];

        let err = policy
            .canonicalize_partitions(&partitions)
            .expect_err("overlap after normalization must fail closed");

        assert!(matches!(
            err,
            FabricError::OverlappingSubjectPartitions { .. }
        ));
    }

    #[test]
    fn normalization_policy_canonicalize_partitions_is_order_stable() {
        let policy = NormalizationPolicy {
            morphisms: vec![SubjectPrefixMorphism::new("svc", "canonical").expect("morphism")],
            reply_space_policy: ReplySpaceCompactionPolicy {
                enabled: true,
                preserve_segments: 3,
            },
        };
        let partitions = vec![
            SubjectPattern::parse("svc.region.two.*").expect("two"),
            SubjectPattern::parse("_INBOX.orders.region.instance.9").expect("reply"),
            SubjectPattern::parse("svc.region.one.>").expect("one"),
        ];

        let canonical = policy
            .canonicalize_partitions(&partitions)
            .expect("canonical partitions");
        let keys = canonical
            .into_iter()
            .map(|pattern| pattern.canonical_key())
            .collect::<Vec<_>>();

        assert_eq!(
            keys,
            vec![
                "_INBOX.orders.region.>".to_string(),
                "canonical.region.one.>".to_string(),
                "canonical.region.two.*".to_string(),
            ]
        );
    }

    #[test]
    fn non_overlapping_validation_rejects_conflicts() {
        let patterns = vec![
            SubjectPattern::parse("orders.created").expect("orders.created"),
            SubjectPattern::parse("orders.*").expect("orders.*"),
        ];
        let err = SubjectPattern::validate_non_overlapping(&patterns).expect_err("should overlap");
        assert!(matches!(
            err,
            FabricError::OverlappingSubjectPartitions { .. }
        ));
    }

    #[test]
    fn cell_id_is_stable_for_same_partition_and_epoch() {
        let partition = SubjectPattern::parse("orders.created").expect("pattern");
        let epoch = CellEpoch::new(7, 3);
        let first = CellId::for_partition(epoch, &partition);
        let second = CellId::for_partition(epoch, &partition);

        assert_eq!(first, second);
        assert_ne!(
            first,
            CellId::for_partition(CellEpoch::new(8, 3), &partition)
        );
    }

    #[test]
    fn alias_subjects_collapse_to_the_same_subject_cell() {
        let policy = PlacementPolicy {
            normalization: NormalizationPolicy {
                morphisms: vec![
                    SubjectPrefixMorphism::new("svc.orders", "orders").expect("morphism"),
                ],
                ..NormalizationPolicy::default()
            },
            ..PlacementPolicy::default()
        };
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-b", StorageClass::Standard, 7),
            candidate("node-c", "rack-c", StorageClass::Standard, 9),
        ];
        let epoch = CellEpoch::new(17, 4);

        let canonical = SubjectCell::new(
            &SubjectPattern::parse("orders.created").expect("canonical"),
            epoch,
            &candidates,
            &policy,
            RepairPolicy::default(),
            DataCapsule::default(),
        )
        .expect("canonical cell");
        let aliased = SubjectCell::new(
            &SubjectPattern::parse("svc.orders.created").expect("aliased"),
            epoch,
            &candidates,
            &policy,
            RepairPolicy::default(),
            DataCapsule::default(),
        )
        .expect("aliased cell");

        assert_eq!(canonical.subject_partition, aliased.subject_partition);
        assert_eq!(canonical.cell_id, aliased.cell_id);
        assert_eq!(canonical.steward_set, aliased.steward_set);
    }

    #[test]
    fn thermal_hysteresis_damps_temperature_flips() {
        let policy = PlacementPolicy::default();

        assert_eq!(
            policy.recommend_temperature(CellTemperature::Warm, ObservedCellLoad::new(64)),
            CellTemperature::Warm
        );
        assert_eq!(
            policy.recommend_temperature(CellTemperature::Warm, ObservedCellLoad::new(32)),
            CellTemperature::Cold
        );
        assert_eq!(
            policy.recommend_temperature(CellTemperature::Hot, ObservedCellLoad::new(768)),
            CellTemperature::Hot
        );
        assert_eq!(
            policy.recommend_temperature(CellTemperature::Hot, ObservedCellLoad::new(256)),
            CellTemperature::Warm
        );
    }

    #[test]
    fn rebalance_budget_limits_steward_churn() {
        let partition = SubjectPattern::parse("orders.created").expect("pattern");
        let policy = PlacementPolicy {
            cold_stewards: 1,
            warm_stewards: 2,
            hot_stewards: 3,
            candidate_pool_size: 5,
            rebalance_budget: RebalanceBudget {
                max_steward_changes: 1,
            },
            ..PlacementPolicy::default()
        };
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-b", StorageClass::Durable, 6),
            candidate("node-c", "rack-c", StorageClass::Standard, 7),
        ];
        let current_stewards = vec![NodeId::new("node-a")];

        let plan = policy
            .plan_rebalance(
                &partition,
                &candidates,
                &current_stewards,
                CellTemperature::Cold,
                ObservedCellLoad::new(2_048),
            )
            .expect("rebalance");

        assert_eq!(plan.next_temperature, CellTemperature::Hot);
        assert_eq!(plan.added_stewards.len(), 1);
        assert!(plan.removed_stewards.is_empty());
        assert_eq!(plan.next_stewards.len(), 2);
        assert!(
            plan.next_stewards
                .iter()
                .any(|node| node.as_str() == "node-a")
        );
    }

    #[test]
    fn rebalance_planning_uses_normalized_subject_partition() {
        let policy = PlacementPolicy {
            cold_stewards: 1,
            warm_stewards: 1,
            hot_stewards: 1,
            candidate_pool_size: 4,
            normalization: NormalizationPolicy {
                morphisms: vec![
                    SubjectPrefixMorphism::new("svc.orders", "orders").expect("morphism"),
                ],
                ..NormalizationPolicy::default()
            },
            ..PlacementPolicy::default()
        };
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-b", StorageClass::Durable, 6),
            candidate("node-c", "rack-c", StorageClass::Standard, 7),
            candidate("node-d", "rack-d", StorageClass::Standard, 8),
            candidate("node-e", "rack-e", StorageClass::Standard, 9),
        ];
        let alias_subjects = [
            "svc.orders.created",
            "svc.orders.updated",
            "svc.orders.cancelled",
            "svc.orders.fulfilled",
            "svc.orders.archived",
            "svc.orders.audit",
            "svc.orders.retry",
            "svc.orders.snapshot",
        ];

        let (aliased, current_stewards) = alias_subjects
            .iter()
            .find_map(|raw| {
                let aliased = SubjectPattern::parse(raw).expect("pattern");
                let canonical = policy.normalization.normalize(&aliased).expect("canonical");
                let raw_stewards = policy
                    .select_stewards(&aliased, &candidates, CellTemperature::Warm)
                    .expect("raw placement");
                let canonical_stewards = policy
                    .select_stewards(&canonical, &candidates, CellTemperature::Warm)
                    .expect("canonical placement");

                (raw_stewards != canonical_stewards).then_some((aliased, canonical_stewards))
            })
            .expect("expected at least one alias subject to hash differently before normalization");

        let plan = policy
            .plan_rebalance(
                &aliased,
                &candidates,
                &current_stewards,
                CellTemperature::Warm,
                ObservedCellLoad::new(256),
            )
            .expect("rebalance");

        assert_eq!(plan.next_stewards, current_stewards);
        assert!(plan.added_stewards.is_empty());
        assert!(plan.removed_stewards.is_empty());
    }

    #[test]
    fn placement_is_deterministic_and_filters_ineligible_nodes() {
        let partition = SubjectPattern::parse("orders.created").expect("pattern");
        let policy = PlacementPolicy {
            cold_stewards: 2,
            warm_stewards: 2,
            hot_stewards: 2,
            candidate_pool_size: 4,
            ..PlacementPolicy::default()
        };
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 8),
            candidate("node-b", "rack-b", StorageClass::Standard, 12),
            StewardCandidate::new(NodeId::new("observer"), "rack-c")
                .with_role(NodeRole::Subscriber)
                .with_health(StewardHealth::Healthy),
        ];

        let first = policy
            .select_stewards(&partition, &candidates, CellTemperature::Warm)
            .expect("placement");
        let second = policy
            .select_stewards(&partition, &candidates, CellTemperature::Warm)
            .expect("placement");

        assert_eq!(first, second);
        assert!(first.iter().all(|node| node.as_str() != "observer"));
    }

    #[test]
    fn candidate_pool_is_duplicate_free_when_trimmed() {
        let partition = SubjectPattern::parse("orders.created").expect("pattern");
        let policy = PlacementPolicy {
            cold_stewards: 2,
            warm_stewards: 2,
            hot_stewards: 2,
            candidate_pool_size: 3,
            placement_hash_salt: 99,
            ..PlacementPolicy::default()
        };
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-b", StorageClass::Durable, 6),
            candidate("node-c", "rack-c", StorageClass::Standard, 7),
            candidate("node-d", "rack-d", StorageClass::Standard, 8),
            candidate("node-e", "rack-e", StorageClass::Standard, 9),
        ];

        let pool = policy
            .candidate_pool(&partition, &candidates, CellTemperature::Warm)
            .expect("candidate pool");
        let unique = pool
            .iter()
            .map(|candidate| candidate.node_id.as_str())
            .collect::<BTreeSet<_>>();

        assert_eq!(pool.len(), 3);
        assert_eq!(unique.len(), pool.len());
    }

    #[test]
    fn hot_cells_widen_steward_set() {
        let partition = SubjectPattern::parse("orders.created").expect("pattern");
        let policy = PlacementPolicy {
            cold_stewards: 1,
            warm_stewards: 2,
            hot_stewards: 3,
            candidate_pool_size: 5,
            ..PlacementPolicy::default()
        };
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-b", StorageClass::Durable, 6),
            candidate("node-c", "rack-c", StorageClass::Standard, 7),
        ];

        let cold = policy
            .select_stewards(&partition, &candidates, CellTemperature::Cold)
            .expect("cold");
        let hot = policy
            .select_stewards(&partition, &candidates, CellTemperature::Hot)
            .expect("hot");

        assert_eq!(cold.len(), 1);
        assert_eq!(hot.len(), 3);
    }

    #[test]
    fn placement_prefers_failure_domain_diversity() {
        let partition = SubjectPattern::parse("orders.created").expect("pattern");
        let policy = PlacementPolicy {
            cold_stewards: 2,
            warm_stewards: 2,
            hot_stewards: 2,
            candidate_pool_size: 4,
            ..PlacementPolicy::default()
        };
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-a", StorageClass::Durable, 5),
            candidate("node-c", "rack-b", StorageClass::Standard, 6),
            candidate("node-d", "rack-c", StorageClass::Standard, 7),
        ];

        let selected = policy
            .select_stewards(&partition, &candidates, CellTemperature::Warm)
            .expect("selected");
        assert_eq!(selected.len(), 2);
        assert!(selected.iter().any(|node| node.as_str() == "node-a"));
        assert!(
            selected
                .iter()
                .any(|node| node.as_str() == "node-c" || node.as_str() == "node-d")
        );
    }

    #[test]
    fn placement_falls_back_to_high_latency_candidates_to_fill_steward_set() {
        let partition = SubjectPattern::parse("orders.created").expect("pattern");
        let policy = PlacementPolicy {
            cold_stewards: 3,
            warm_stewards: 3,
            hot_stewards: 3,
            candidate_pool_size: 3,
            max_latency_millis: 20,
            ..PlacementPolicy::default()
        };
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-b", StorageClass::Standard, 7),
            candidate("node-c", "rack-c", StorageClass::Standard, 250),
        ];

        let selected = policy
            .select_stewards(&partition, &candidates, CellTemperature::Warm)
            .expect("selected");

        assert_eq!(selected.len(), 3);
        assert!(selected.iter().any(|node| node.as_str() == "node-c"));
    }

    #[test]
    fn hot_placement_prefers_explicit_repair_witness_capacity() {
        let partition = SubjectPattern::parse("orders.created").expect("pattern");
        let policy = PlacementPolicy {
            cold_stewards: 1,
            warm_stewards: 1,
            hot_stewards: 1,
            candidate_pool_size: 2,
            max_latency_millis: 20,
            ..PlacementPolicy::default()
        };
        let candidates = vec![
            StewardCandidate::new(NodeId::new("node-a"), "rack-a")
                .with_role(NodeRole::Steward)
                .with_storage_class(StorageClass::Standard)
                .with_latency_millis(5),
            StewardCandidate::new(NodeId::new("node-b"), "rack-b")
                .with_role(NodeRole::Steward)
                .with_role(NodeRole::RepairWitness)
                .with_storage_class(StorageClass::Standard)
                .with_latency_millis(5),
        ];

        let warm = policy
            .select_stewards(&partition, &candidates, CellTemperature::Warm)
            .expect("warm");
        let hot = policy
            .select_stewards(&partition, &candidates, CellTemperature::Hot)
            .expect("hot");

        assert_eq!(warm, vec![NodeId::new("node-a")]);
        assert_eq!(hot, vec![NodeId::new("node-b")]);
    }

    #[test]
    fn subject_cell_construction_builds_capsules_and_compacts_reply_space() {
        let subject_partition =
            SubjectPattern::parse("_INBOX.orders.region.instance.123").expect("pattern");
        let policy = PlacementPolicy {
            cold_stewards: 2,
            warm_stewards: 2,
            hot_stewards: 3,
            candidate_pool_size: 4,
            normalization: NormalizationPolicy {
                morphisms: Vec::new(),
                reply_space_policy: ReplySpaceCompactionPolicy {
                    enabled: true,
                    preserve_segments: 3,
                },
            },
            ..PlacementPolicy::default()
        };
        let data_capsule = DataCapsule {
            temperature: CellTemperature::Warm,
            retained_message_blocks: 4,
        };
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-b", StorageClass::Standard, 6),
            candidate("node-c", "rack-c", StorageClass::Standard, 7),
        ];

        let cell = SubjectCell::new(
            &subject_partition,
            CellEpoch::new(11, 2),
            &candidates,
            &policy,
            RepairPolicy::default(),
            data_capsule,
        )
        .expect("cell");

        assert_eq!(
            cell.subject_partition.canonical_key(),
            "_INBOX.orders.region.>"
        );
        assert_eq!(
            cell.control_capsule.active_sequencer_holder(),
            cell.steward_set.first()
        );
        assert_eq!(cell.steward_set.len(), 2);
    }

    fn control_capsule() -> ControlCapsuleV1 {
        let epoch = CellEpoch::new(23, 4);
        let partition = SubjectPattern::parse("orders.created").expect("pattern");
        let cell_id = CellId::for_partition(epoch, &partition);
        ControlCapsuleV1::new(
            cell_id,
            vec![NodeId::new("node-a"), NodeId::new("node-b")],
            epoch,
        )
    }

    fn rebalance_policy() -> PlacementPolicy {
        PlacementPolicy {
            cold_stewards: 1,
            warm_stewards: 3,
            hot_stewards: 4,
            candidate_pool_size: 6,
            rebalance_budget: RebalanceBudget {
                max_steward_changes: 3,
            },
            ..PlacementPolicy::default()
        }
    }

    fn rebalance_candidates() -> Vec<StewardCandidate> {
        vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-b", StorageClass::Durable, 6),
            candidate("node-c", "rack-c", StorageClass::Standard, 7),
            candidate("node-d", "rack-d", StorageClass::Standard, 8),
            candidate("node-e", "rack-e", StorageClass::Standard, 9),
            candidate("node-f", "rack-f", StorageClass::Standard, 10),
        ]
    }

    fn cold_subject_cell(candidates: &[StewardCandidate], policy: &PlacementPolicy) -> SubjectCell {
        SubjectCell::new(
            &SubjectPattern::parse("orders.created").expect("pattern"),
            CellEpoch::new(11, 2),
            candidates,
            policy,
            RepairPolicy {
                recoverability_target: 3,
                cold_witnesses: 1,
                hot_witnesses: 2,
            },
            DataCapsule::default(),
        )
        .expect("cold cell")
    }

    fn warm_subject_cell(candidates: &[StewardCandidate], policy: &PlacementPolicy) -> SubjectCell {
        SubjectCell::new(
            &SubjectPattern::parse("orders.created").expect("pattern"),
            CellEpoch::new(11, 2),
            candidates,
            policy,
            RepairPolicy {
                recoverability_target: 3,
                cold_witnesses: 1,
                hot_witnesses: 2,
            },
            DataCapsule {
                temperature: CellTemperature::Warm,
                retained_message_blocks: 4,
            },
        )
        .expect("warm cell")
    }

    fn hot_subject_cell(candidates: &[StewardCandidate], policy: &PlacementPolicy) -> SubjectCell {
        SubjectCell::new(
            &SubjectPattern::parse("orders.created").expect("pattern"),
            CellEpoch::new(11, 2),
            candidates,
            policy,
            RepairPolicy {
                recoverability_target: 3,
                cold_witnesses: 1,
                hot_witnesses: 2,
            },
            DataCapsule {
                temperature: CellTemperature::Hot,
                retained_message_blocks: 6,
            },
        )
        .expect("hot cell")
    }

    fn repair_bindings_for(
        cell: &SubjectCell,
        plan: &RebalancePlan,
        candidates: &[StewardCandidate],
        retention_generation: u64,
        required_holders: usize,
    ) -> Vec<RepairSymbolBinding> {
        let mut holders = plan.next_stewards.clone();
        for candidate in candidates {
            if holders.len() >= required_holders {
                break;
            }
            if contains_node(&holders, &candidate.node_id) || !candidate.can_repair() {
                continue;
            }
            holders.push(candidate.node_id.clone());
        }
        holders
            .into_iter()
            .map(|node_id| RepairSymbolBinding::new(node_id, cell.epoch, retention_generation))
            .collect()
    }

    fn successful_rebalance_evidence(
        cell: &SubjectCell,
        plan: &RebalancePlan,
        candidates: &[StewardCandidate],
        retention_generation: u64,
    ) -> RebalanceCutEvidence {
        let required_holders = cell
            .repair_policy
            .minimum_repair_holders(plan.next_temperature, plan.next_stewards.len());
        RebalanceCutEvidence {
            next_sequencer: plan
                .added_stewards
                .first()
                .cloned()
                .unwrap_or_else(|| plan.next_stewards[0].clone()),
            retention_generation,
            obligation_summary: RebalanceObligationSummary {
                publish_obligations_below_cut: 0,
                active_consumer_leases: 2,
                transferred_consumer_leases: 2,
                ambiguous_consumer_lease_owners: 0,
                active_reply_rights: 1,
                reissued_reply_rights: 1,
                dangling_reply_rights: 0,
            },
            repair_symbols: repair_bindings_for(
                cell,
                plan,
                candidates,
                retention_generation,
                required_holders,
            ),
        }
    }

    fn split_capable_kernel(
        name: &str,
        interference_class: &str,
        obligation_footprint: &str,
    ) -> ProtocolKernel {
        ProtocolKernel::new(name, DeliveryClass::ObligationBacked)
            .with_interference_class(interference_class)
            .with_obligation_footprint(obligation_footprint)
            .allow_reordering()
            .allow_parallel_issue()
    }

    fn semantic_family(
        family_id: &str,
        kernel: ProtocolKernel,
        shared_state_footprint: &str,
        estimated_work_units: usize,
    ) -> SemanticConversationFamily {
        SemanticConversationFamily::new(
            family_id,
            SubjectPattern::parse("orders.created").expect("family subject"),
            kernel,
        )
        .with_shared_state_footprint(shared_state_footprint)
        .with_estimated_work_units(estimated_work_units)
    }

    fn subscribe_capability(subject: &str) -> FabricCapability {
        FabricCapability::Subscribe {
            subject: SubjectPattern::parse(subject).expect("capability subject"),
        }
    }

    fn discovery_policy(viewer_capabilities: Vec<FabricCapability>) -> DiscoveryNegotiationPolicy {
        DiscoveryNegotiationPolicy {
            trusted_issuers: BTreeSet::from([NodeId::new("admission-authority")]),
            supported_policy_versions: BTreeSet::from([1, 3]),
            viewer_capabilities,
            lease_ttl_millis: 30_000,
        }
    }

    fn discovery_interest(subject: &str, subscribers: u64) -> DiscoveryInterestSummaryEntry {
        DiscoveryInterestSummaryEntry {
            subject: SubjectPattern::parse(subject).expect("interest subject"),
            subscribers,
        }
    }

    fn discovery_credential(
        node: &str,
        admitted_capabilities: Vec<FabricCapability>,
    ) -> DiscoveryAdmissionCredential {
        DiscoveryAdmissionCredential {
            subject: NodeId::new(node),
            issuer: NodeId::new("admission-authority"),
            membership_epoch: 11,
            admitted_capabilities,
            signature: format!("sig:{node}:v1"),
        }
    }

    fn discovery_hello(
        node: &str,
        bootstrap: DiscoveryBootstrap,
        capability_set: Vec<FabricCapability>,
        credential_capabilities: Vec<FabricCapability>,
        interest_summary: Vec<DiscoveryInterestSummaryEntry>,
        stewardship_leases: Vec<DiscoveryStewardLeaseView>,
        recent_control_epochs: Vec<DiscoveryControlEpochView>,
    ) -> DiscoveryHello {
        let suggested_cells = recent_control_epochs
            .iter()
            .map(|view| view.cell_id)
            .collect();
        DiscoveryHello {
            node_id: NodeId::new(node),
            bootstrap,
            capability_set,
            credential: discovery_credential(node, credential_capabilities),
            supported_policy_versions: BTreeSet::from([2, 3]),
            resource_budget: DiscoveryResourceBudget {
                storage_bytes_available: 64 * 1024 * 1024,
                uplink_kib_per_sec: 4_096,
                repair_slots: 3,
            },
            interest_summary,
            stewardship_leases,
            recent_control_epochs,
            advisory_hints: DiscoveryAdvisoryHints {
                membership: Some(MembershipRecord::new(
                    4,
                    crate::messaging::control::MembershipState::Healthy,
                    1_234,
                    180,
                )),
                suggested_cells,
            },
        }
    }

    fn discovery_blinded_fingerprint(session_id: DiscoverySessionId, subject: &str) -> u64 {
        stable_hash((
            "fabric::discovery::interest",
            session_id.raw(),
            SubjectPattern::parse(subject)
                .expect("blinded subject")
                .canonical_key(),
        ))
    }

    #[test]
    fn discovery_session_establishes_handshake_with_explicit_lease_obligation() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = warm_subject_cell(&candidates, &policy);
        let capability = subscribe_capability("tenant.alpha.>");
        let hello = discovery_hello(
            "peer-a",
            DiscoveryBootstrap::SeedList(vec![NodeId::new("seed-a"), NodeId::new("seed-b")]),
            vec![capability.clone()],
            vec![capability.clone()],
            vec![discovery_interest("tenant.alpha.orders.>", 9)],
            vec![DiscoveryStewardLeaseView {
                cell_id: cell.cell_id,
                lease: cell
                    .control_capsule
                    .active_sequencer_lease()
                    .expect("active lease"),
            }],
            vec![DiscoveryControlEpochView {
                cell_id: cell.cell_id,
                control_epoch: cell.control_capsule.control_epoch(),
            }],
        );

        let session = DiscoverySession::establish(
            NodeId::new("local-a"),
            &hello,
            &discovery_policy(vec![capability]),
        )
        .expect("session");

        assert_eq!(session.state, DiscoverySessionState::Established);
        assert_eq!(session.policy_version, 3);
        assert_eq!(session.authoritative_stewardship.len(), 1);
        assert_eq!(session.lease_obligation.peer_node, NodeId::new("peer-a"));
        assert_eq!(session.lease_obligation.ttl_millis, 30_000);
        assert_eq!(
            session
                .transitions()
                .iter()
                .map(DiscoverySessionTransition::kind)
                .collect::<Vec<_>>(),
            vec![
                "bootstrap_validated",
                "peer_authenticated",
                "interest_summary_scoped",
                "authority_validated",
                "lease_bound",
                "established",
            ]
        );
    }

    #[test]
    fn discovery_session_rejects_capability_escalation_outside_signed_admission() {
        let granted = subscribe_capability("tenant.alpha.orders.>");
        let escalated = subscribe_capability("tenant.alpha.>");
        let hello = discovery_hello(
            "peer-b",
            DiscoveryBootstrap::SelfDiscover,
            vec![escalated.clone()],
            vec![granted],
            vec![discovery_interest("tenant.alpha.orders.>", 3)],
            Vec::new(),
            Vec::new(),
        );

        let err = DiscoverySession::establish(
            NodeId::new("local-a"),
            &hello,
            &discovery_policy(vec![subscribe_capability("tenant.alpha.>")]),
        )
        .expect_err("capability escalation must fail");

        assert_eq!(
            err,
            DiscoveryError::CapabilityEscalation {
                node: NodeId::new("peer-b"),
                capability: escalated,
            }
        );
    }

    #[test]
    fn discovery_tail_wildcard_capability_does_not_cover_bare_prefix() {
        let granted = subscribe_capability("tenant.alpha.>");
        let bare_prefix = subscribe_capability("tenant.alpha");
        let bare_interest = SubjectPattern::parse("tenant.alpha").expect("bare interest");

        assert!(
            !fabric_capability_covers(&granted, &bare_prefix),
            "tail wildcard grants require at least one requested suffix token"
        );
        assert!(
            !capabilities_cover_interest_subject(std::slice::from_ref(&granted), &bare_interest),
            "peer interest summaries must not widen tail wildcard grants to the bare prefix"
        );
        assert!(
            !capabilities_allow_interest_visibility(&[granted], &bare_interest),
            "viewer visibility must use the same fail-closed subject coverage"
        );
    }

    #[test]
    fn discovery_session_rejects_bare_prefix_capability_under_tail_admission() {
        let admitted = subscribe_capability("tenant.alpha.>");
        let escalated = subscribe_capability("tenant.alpha");
        let hello = discovery_hello(
            "peer-b2",
            DiscoveryBootstrap::SelfDiscover,
            vec![escalated.clone()],
            vec![admitted],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        let err = DiscoverySession::establish(
            NodeId::new("local-a"),
            &hello,
            &discovery_policy(vec![subscribe_capability("tenant.alpha.>")]),
        )
        .expect_err("tail wildcard admission must not authorize the bare prefix");

        assert_eq!(
            err,
            DiscoveryError::CapabilityEscalation {
                node: NodeId::new("peer-b2"),
                capability: escalated,
            }
        );
    }

    #[test]
    fn discovery_rejects_bare_prefix_interest_under_tail_capability() {
        let capability = subscribe_capability("tenant.alpha.>");
        let bare_interest = SubjectPattern::parse("tenant.alpha").expect("bare interest");
        let hello = discovery_hello(
            "peer-c1",
            DiscoveryBootstrap::SelfDiscover,
            vec![capability.clone()],
            vec![capability],
            vec![DiscoveryInterestSummaryEntry {
                subject: bare_interest.clone(),
                subscribers: 4,
            }],
            Vec::new(),
            Vec::new(),
        );

        let err = DiscoverySession::establish(
            NodeId::new("local-a"),
            &hello,
            &discovery_policy(vec![subscribe_capability("tenant.alpha.>")]),
        )
        .expect_err("tail wildcard capability must not authorize bare prefix interest");

        assert_eq!(
            err,
            DiscoveryError::InterestSummaryOutsideCapabilitySet {
                node: NodeId::new("peer-c1"),
                subject: bare_interest,
            }
        );
    }

    #[test]
    fn discovery_interest_summary_blinds_namespaces_outside_viewer_capability() {
        let hello = discovery_hello(
            "peer-c",
            DiscoveryBootstrap::SelfDiscover,
            vec![
                subscribe_capability("tenant.alpha.>"),
                subscribe_capability("tenant.beta.>"),
            ],
            vec![
                subscribe_capability("tenant.alpha.>"),
                subscribe_capability("tenant.beta.>"),
            ],
            vec![
                discovery_interest("tenant.alpha.orders.>", 7),
                discovery_interest("tenant.beta.orders.>", 11),
            ],
            Vec::new(),
            Vec::new(),
        );

        let session = DiscoverySession::establish(
            NodeId::new("local-a"),
            &hello,
            &discovery_policy(vec![subscribe_capability("tenant.alpha.>")]),
        )
        .expect("session");

        assert_eq!(
            session.peer_interest_advertisements[0],
            DiscoveryInterestAdvertisement::Scoped {
                subject: SubjectPattern::parse("tenant.alpha.orders.>").expect("alpha"),
                subscribers: 7,
            }
        );
        assert_eq!(
            session.peer_interest_advertisements[1],
            DiscoveryInterestAdvertisement::Blinded {
                subject_fingerprint: discovery_blinded_fingerprint(
                    session.session_id,
                    "tenant.beta.orders.>",
                ),
                subscribers: 11,
            }
        );
    }

    #[test]
    fn discovery_rejects_interest_summary_outside_peer_capability_scope() {
        let capability = subscribe_capability("tenant.alpha.>");
        let hello = discovery_hello(
            "peer-c2",
            DiscoveryBootstrap::SelfDiscover,
            vec![capability.clone()],
            vec![capability],
            vec![discovery_interest("tenant.beta.orders.>", 11)],
            Vec::new(),
            Vec::new(),
        );

        let err = DiscoverySession::establish(
            NodeId::new("local-a"),
            &hello,
            &discovery_policy(vec![subscribe_capability("tenant.alpha.>")]),
        )
        .expect_err("interest summary outside peer capability scope must fail");

        assert_eq!(
            err,
            DiscoveryError::InterestSummaryOutsideCapabilitySet {
                node: NodeId::new("peer-c2"),
                subject: SubjectPattern::parse("tenant.beta.orders.>").expect("beta"),
            }
        );
    }

    #[test]
    fn discovery_namespace_visibility_is_narrower_than_membership() {
        let hello = discovery_hello(
            "peer-d",
            DiscoveryBootstrap::SelfDiscover,
            vec![subscribe_capability("tenant.alpha.>")],
            vec![subscribe_capability("tenant.alpha.>")],
            vec![discovery_interest("tenant.alpha.orders.>", 5)],
            Vec::new(),
            Vec::new(),
        );

        let session = DiscoverySession::establish(
            NodeId::new("local-a"),
            &hello,
            &discovery_policy(Vec::new()),
        )
        .expect("session");

        assert!(session.advisory_hints.membership.is_some());
        assert_eq!(
            session.peer_interest_advertisements,
            vec![DiscoveryInterestAdvertisement::Blinded {
                subject_fingerprint: discovery_blinded_fingerprint(
                    session.session_id,
                    "tenant.alpha.orders.>",
                ),
                subscribers: 5,
            }]
        );
    }

    #[test]
    fn discovery_session_blinding_is_not_linkable_across_distinct_credentials() {
        let hello_v1 = discovery_hello(
            "peer-d1",
            DiscoveryBootstrap::SelfDiscover,
            vec![subscribe_capability("tenant.alpha.>")],
            vec![subscribe_capability("tenant.alpha.>")],
            vec![discovery_interest("tenant.alpha.orders.>", 5)],
            Vec::new(),
            Vec::new(),
        );
        let mut hello_v2 = hello_v1.clone();
        hello_v2.credential.signature = "sig:peer-d1:v2".to_owned();

        let policy = discovery_policy(Vec::new());
        let session_v1 = DiscoverySession::establish(NodeId::new("local-a"), &hello_v1, &policy)
            .expect("session v1");
        let session_v2 = DiscoverySession::establish(NodeId::new("local-a"), &hello_v2, &policy)
            .expect("session v2");

        assert_ne!(session_v1.session_id, session_v2.session_id);
        assert_ne!(
            session_v1.peer_interest_advertisements,
            session_v2.peer_interest_advertisements
        );
    }

    #[test]
    fn discovery_session_id_changes_when_handshake_material_changes_without_rotating_credential() {
        let hello_v1 = discovery_hello(
            "peer-d2",
            DiscoveryBootstrap::SelfDiscover,
            vec![subscribe_capability("tenant.alpha.>")],
            vec![subscribe_capability("tenant.alpha.>")],
            vec![discovery_interest("tenant.alpha.orders.>", 5)],
            Vec::new(),
            Vec::new(),
        );
        let mut hello_v2 = hello_v1.clone();
        hello_v2.resource_budget.repair_slots += 1;

        let policy = discovery_policy(Vec::new());
        let session_v1 = DiscoverySession::establish(NodeId::new("local-a"), &hello_v1, &policy)
            .expect("session v1");
        let session_v2 = DiscoverySession::establish(NodeId::new("local-a"), &hello_v2, &policy)
            .expect("session v2");

        assert_ne!(
            session_v1.session_id, session_v2.session_id,
            "distinct hello transcripts must not collapse to the same session id under a reused credential"
        );
        assert_ne!(
            session_v1.peer_interest_advertisements, session_v2.peer_interest_advertisements,
            "session-scoped blinding must rotate when the discovery transcript changes"
        );
    }

    #[test]
    fn discovery_session_id_changes_when_local_negotiation_policy_changes() {
        let hello = discovery_hello(
            "peer-d3",
            DiscoveryBootstrap::SelfDiscover,
            vec![subscribe_capability("tenant.alpha.>")],
            vec![subscribe_capability("tenant.alpha.>")],
            vec![discovery_interest("tenant.alpha.orders.>", 5)],
            Vec::new(),
            Vec::new(),
        );
        let policy_v1 = discovery_policy(Vec::new());
        let mut policy_v2 = policy_v1.clone();
        policy_v2.lease_ttl_millis = 45_000;

        let session_v1 = DiscoverySession::establish(NodeId::new("local-a"), &hello, &policy_v1)
            .expect("session v1");
        let session_v2 = DiscoverySession::establish(NodeId::new("local-a"), &hello, &policy_v2)
            .expect("session v2");

        assert_ne!(
            session_v1.session_id, session_v2.session_id,
            "local negotiation policy changes must produce a distinct discovery session id"
        );
        assert_ne!(
            session_v1.lease_obligation, session_v2.lease_obligation,
            "lease obligation identity must track the effective local policy"
        );
    }

    #[test]
    fn discovery_sybil_resistance_rejects_untrusted_issuer() {
        let capability = subscribe_capability("tenant.alpha.>");
        let mut hello = discovery_hello(
            "peer-e",
            DiscoveryBootstrap::SelfDiscover,
            vec![capability.clone()],
            vec![capability],
            vec![discovery_interest("tenant.alpha.orders.>", 2)],
            Vec::new(),
            Vec::new(),
        );
        hello.credential.issuer = NodeId::new("rogue-issuer");

        let err = DiscoverySession::establish(
            NodeId::new("local-a"),
            &hello,
            &discovery_policy(vec![subscribe_capability("tenant.alpha.>")]),
        )
        .expect_err("untrusted issuer must fail");

        assert_eq!(
            err,
            DiscoveryError::UntrustedCredentialIssuer {
                issuer: NodeId::new("rogue-issuer"),
            }
        );
    }

    #[test]
    fn discovery_stale_steward_leases_do_not_become_authoritative() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = warm_subject_cell(&candidates, &policy);
        let capability = subscribe_capability("tenant.alpha.>");
        let stale_lease = cell
            .control_capsule
            .active_sequencer_lease()
            .expect("active lease");
        let hello = discovery_hello(
            "peer-f",
            DiscoveryBootstrap::SelfDiscover,
            vec![capability.clone()],
            vec![capability.clone()],
            vec![discovery_interest("tenant.alpha.orders.>", 4)],
            vec![DiscoveryStewardLeaseView {
                cell_id: cell.cell_id,
                lease: stale_lease,
            }],
            vec![DiscoveryControlEpochView {
                cell_id: cell.cell_id,
                control_epoch: ControlEpoch::new(
                    cell.epoch,
                    cell.control_capsule.policy_revision + 1,
                ),
            }],
        );

        let session = DiscoverySession::establish(
            NodeId::new("local-a"),
            &hello,
            &discovery_policy(vec![capability]),
        )
        .expect("session");

        assert!(
            session.authoritative_stewardship.is_empty(),
            "stale lease should remain advisory until backed by the current control epoch"
        );
    }

    #[test]
    fn discovery_rejects_authority_evidence_from_wrong_membership_epoch() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = warm_subject_cell(&candidates, &policy);
        let capability = subscribe_capability("tenant.alpha.>");
        let mut hello = discovery_hello(
            "peer-h",
            DiscoveryBootstrap::SelfDiscover,
            vec![capability.clone()],
            vec![capability.clone()],
            vec![discovery_interest("tenant.alpha.orders.>", 4)],
            vec![DiscoveryStewardLeaseView {
                cell_id: cell.cell_id,
                lease: cell
                    .control_capsule
                    .active_sequencer_lease()
                    .expect("active lease"),
            }],
            vec![DiscoveryControlEpochView {
                cell_id: cell.cell_id,
                control_epoch: cell.control_capsule.control_epoch(),
            }],
        );
        hello.recent_control_epochs[0].control_epoch = ControlEpoch::new(
            CellEpoch::new(12, cell.epoch.generation),
            cell.control_capsule.policy_revision,
        );

        let err = DiscoverySession::establish(
            NodeId::new("local-a"),
            &hello,
            &discovery_policy(vec![capability]),
        )
        .expect_err("authority evidence from the wrong membership epoch must fail");

        assert_eq!(
            err,
            DiscoveryError::ControlEpochMembershipMismatch {
                node: NodeId::new("peer-h"),
                cell_id: cell.cell_id,
                expected_membership_epoch: 11,
                actual_membership_epoch: 12,
            }
        );
    }

    #[test]
    fn discovery_rejects_conflicting_current_authoritative_leases() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = warm_subject_cell(&candidates, &policy);
        let capability = subscribe_capability("tenant.alpha.>");
        let current_control_epoch = cell.control_capsule.control_epoch();
        let mut conflicting_lease = cell
            .control_capsule
            .active_sequencer_lease()
            .expect("active lease");
        conflicting_lease.holder = NodeId::new("node-z");
        let hello = discovery_hello(
            "peer-i",
            DiscoveryBootstrap::SelfDiscover,
            vec![capability.clone()],
            vec![capability.clone()],
            vec![discovery_interest("tenant.alpha.orders.>", 4)],
            vec![
                DiscoveryStewardLeaseView {
                    cell_id: cell.cell_id,
                    lease: cell
                        .control_capsule
                        .active_sequencer_lease()
                        .expect("active lease"),
                },
                DiscoveryStewardLeaseView {
                    cell_id: cell.cell_id,
                    lease: conflicting_lease,
                },
            ],
            vec![DiscoveryControlEpochView {
                cell_id: cell.cell_id,
                control_epoch: current_control_epoch,
            }],
        );

        let err = DiscoverySession::establish(
            NodeId::new("local-a"),
            &hello,
            &discovery_policy(vec![capability]),
        )
        .expect_err("conflicting current leases must fail");

        assert_eq!(
            err,
            DiscoveryError::ConflictingAuthoritativeStewardLease {
                node: NodeId::new("peer-i"),
                cell_id: cell.cell_id,
            }
        );
    }

    #[test]
    fn discovery_session_transcript_is_replayable_for_identical_inputs() {
        let capability = subscribe_capability("tenant.alpha.>");
        let hello = discovery_hello(
            "peer-g",
            DiscoveryBootstrap::SeedList(vec![NodeId::new("seed-a")]),
            vec![capability.clone()],
            vec![capability.clone()],
            vec![discovery_interest("tenant.alpha.orders.>", 6)],
            Vec::new(),
            Vec::new(),
        );
        let policy = discovery_policy(vec![capability]);

        let first = DiscoverySession::establish(NodeId::new("local-a"), &hello, &policy)
            .expect("first session");
        let second = DiscoverySession::establish(NodeId::new("local-a"), &hello, &policy)
            .expect("second session");

        assert_eq!(first.session_id, second.session_id);
        assert_eq!(first.transitions(), second.transitions());
        assert_eq!(
            first.peer_interest_advertisements,
            second.peer_interest_advertisements
        );
    }

    #[test]
    fn control_capsule_v1_fences_stale_sequencer_leases() {
        let mut capsule = control_capsule();
        let original = capsule
            .active_sequencer_lease()
            .expect("initial sequencer lease");

        let fence = capsule
            .fence_sequencer(NodeId::new("node-b"))
            .expect("fence should succeed");

        assert_eq!(fence.previous_holder, NodeId::new("node-a"));
        assert_eq!(fence.next_holder, NodeId::new("node-b"));

        let err = capsule
            .authoritative_append(&original)
            .expect_err("old sequencer lease must be fenced");
        assert!(matches!(
            err,
            ControlCapsuleError::StaleSequencerLease {
                current_holder,
                current_fence_generation,
                ..
            } if current_holder == NodeId::new("node-b")
                && current_fence_generation == fence.fence_generation
        ));

        let current = capsule
            .active_sequencer_lease()
            .expect("refreshed sequencer lease");
        let certificate = capsule
            .authoritative_append(&current)
            .expect("fresh lease should append");
        assert_eq!(certificate.identity.sequence, 1);
        assert_eq!(certificate.sequencer, NodeId::new("node-b"));
    }

    #[test]
    fn control_capsule_v1_authoritative_appends_are_monotonic_within_epoch() {
        let mut capsule = control_capsule();
        let lease = capsule
            .active_sequencer_lease()
            .expect("initial sequencer lease");

        let first = capsule
            .authoritative_append(&lease)
            .expect("first append should commit");
        let second = capsule
            .authoritative_append(&lease)
            .expect("second append should commit");

        assert_eq!(first.identity.cell_id, second.identity.cell_id);
        assert_eq!(first.identity.epoch, second.identity.epoch);
        assert_eq!(first.identity.sequence, 1);
        assert_eq!(second.identity.sequence, 2);
        assert!(first.identity < second.identity);
    }

    #[test]
    fn control_capsule_v1_reconfiguration_uses_joint_overlap_and_single_live_sequencer() {
        let mut capsule = control_capsule();
        let original = capsule
            .active_sequencer_lease()
            .expect("initial sequencer lease");

        let err = capsule
            .reconfigure(
                vec![NodeId::new("node-c"), NodeId::new("node-d")],
                NodeId::new("node-c"),
            )
            .expect_err("overlap-free reconfiguration must fail");
        assert_eq!(err, ControlCapsuleError::JointConfigRequiresOverlap);

        let joint = capsule
            .reconfigure(
                vec![NodeId::new("node-a"), NodeId::new("node-c")],
                NodeId::new("node-c"),
            )
            .expect("joint reconfiguration should succeed");

        assert_eq!(
            joint.old_stewards,
            vec![NodeId::new("node-a"), NodeId::new("node-b")]
        );
        assert_eq!(
            joint.new_stewards,
            vec![NodeId::new("node-a"), NodeId::new("node-c")]
        );
        assert_eq!(joint.next_sequencer, NodeId::new("node-c"));
        assert_eq!(capsule.policy_revision, 2);
        assert_eq!(
            capsule.active_sequencer_holder().map(NodeId::as_str),
            Some("node-c")
        );
        assert_eq!(capsule.joint_config_history, vec![joint.clone()]);

        let stale = capsule
            .authoritative_append(&original)
            .expect_err("old sequencer must not decide after fencing");
        assert!(matches!(
            stale,
            ControlCapsuleError::StaleSequencerLease {
                current_holder,
                ..
            } if current_holder == NodeId::new("node-c")
        ));

        let current = capsule
            .active_sequencer_lease()
            .expect("new sequencer lease");
        let certificate = capsule
            .authoritative_append(&current)
            .expect("new sequencer should be able to append");
        assert_eq!(certificate.sequencer, NodeId::new("node-c"));
        assert_eq!(certificate.control_epoch, joint.control_epoch);
    }

    #[test]
    fn control_capsule_v1_reconfiguration_rejects_duplicate_stewards_without_mutation() {
        let mut capsule = control_capsule();

        let err = capsule
            .reconfigure(
                vec![NodeId::new("node-a"), NodeId::new("node-a")],
                NodeId::new("node-a"),
            )
            .expect_err("duplicate steward sets must fail closed");
        assert_eq!(
            err,
            ControlCapsuleError::DuplicateSteward {
                node: NodeId::new("node-a")
            }
        );
        assert_eq!(
            capsule.steward_pool,
            vec![NodeId::new("node-a"), NodeId::new("node-b")]
        );
        assert_eq!(capsule.policy_revision, 1);
        assert_eq!(
            capsule.active_sequencer_holder().map(NodeId::as_str),
            Some("node-a")
        );
    }

    #[test]
    fn control_capsule_v1_replicated_append_is_idempotent_or_stale() {
        let mut capsule = control_capsule();
        let lease = capsule
            .active_sequencer_lease()
            .expect("initial sequencer lease");

        let first = capsule
            .authoritative_append(&lease)
            .expect("first append should commit");
        let second = capsule
            .authoritative_append(&lease)
            .expect("second append should commit");
        assert_ne!(first.identity, second.identity);

        let outcome = capsule
            .accept_replicated_append(first.clone())
            .expect("duplicate delivery should collapse");
        assert_eq!(outcome, ReplicatedAppendOutcome::IdempotentNoop(first));

        capsule
            .fence_sequencer(NodeId::new("node-b"))
            .expect("fence should succeed");
        let stale = capsule
            .accept_replicated_append(second.clone())
            .expect("late delivery must reduce deterministically");
        assert_eq!(
            stale,
            ReplicatedAppendOutcome::StaleReject {
                identity: second.identity.clone(),
                attempted_fence_generation: second.fence_generation,
                current_fence_generation: capsule.sequencer_lease_generation,
            }
        );
    }

    #[test]
    fn control_capsule_v1_cursor_authority_transfer_fences_old_holder() {
        let mut capsule = control_capsule();
        let original = capsule
            .cursor_authority_lease()
            .cloned()
            .expect("initial cursor-authority lease");

        let transferred = capsule
            .transfer_cursor_authority(NodeId::new("node-b"))
            .expect("steward transfer should succeed");

        capsule
            .validate_cursor_authority(&transferred)
            .expect("fresh cursor-authority lease should validate");
        let err = capsule
            .validate_cursor_authority(&original)
            .expect_err("old cursor-authority lease must be fenced");
        assert!(matches!(
            err,
            ControlCapsuleError::StaleCursorAuthorityLease {
                current_holder,
                current_fence_generation,
                ..
            } if current_holder == NodeId::new("node-b")
                && current_fence_generation == capsule.sequencer_lease_generation
        ));
    }

    #[test]
    fn control_capsule_v1_cursor_authority_transfer_rejects_foreign_holder_without_mutation() {
        let mut capsule = control_capsule();
        let original = capsule
            .cursor_authority_lease()
            .cloned()
            .expect("initial cursor-authority lease");
        let original_generation = capsule.sequencer_lease_generation;

        let err = capsule
            .transfer_cursor_authority(NodeId::new("consumer-a"))
            .expect_err("foreign holders must be rejected");
        assert_eq!(
            err,
            ControlCapsuleError::UnknownSteward {
                node: NodeId::new("consumer-a")
            }
        );
        assert_eq!(capsule.cursor_authority_lease(), Some(&original));
        assert_eq!(capsule.sequencer_lease_generation, original_generation);
    }

    #[test]
    fn subject_cell_certified_rebalance_advances_epoch_and_fences_old_sequencer() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let observed_load = ObservedCellLoad::new(256);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let original = cell
            .control_capsule
            .active_sequencer_lease()
            .expect("original sequencer lease");
        let evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 7);
        let next_sequencer = evidence.next_sequencer.clone();

        let mut certified = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect("certified rebalance");

        assert_eq!(certified.plan, plan);
        assert_eq!(certified.control_append.identity.cell_id, cell.cell_id);
        assert_eq!(certified.control_append.identity.epoch, cell.epoch);
        assert_eq!(
            certified.resulting_cell.epoch,
            CellEpoch::new(cell.epoch.membership_epoch, cell.epoch.generation + 1)
        );
        assert_eq!(certified.resulting_cell.steward_set, plan.next_stewards);
        assert_eq!(
            certified.resulting_cell.data_capsule.temperature,
            CellTemperature::Warm
        );
        assert_eq!(
            certified
                .resulting_cell
                .control_capsule
                .active_sequencer_holder(),
            Some(&next_sequencer)
        );
        assert_eq!(
            certified
                .resulting_cell
                .control_capsule
                .cursor_authority_lease()
                .map(|lease| &lease.holder),
            Some(&next_sequencer)
        );

        let stale = certified
            .resulting_cell
            .control_capsule
            .authoritative_append(&original)
            .expect_err("pre-cut sequencer lease must be fenced");
        assert!(matches!(
            stale,
            ControlCapsuleError::StaleSequencerLease {
                current_holder,
                current_fence_generation,
                ..
            } if current_holder == next_sequencer
                && current_fence_generation == certified.resulting_cell.epoch.generation
        ));
    }

    #[test]
    fn subject_cell_certified_rebalance_requires_consumer_lease_transfer() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let observed_load = ObservedCellLoad::new(256);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let mut evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 9);
        evidence.obligation_summary.transferred_consumer_leases = 1;

        let err = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect_err("consumer lease transfer gaps must fail closed");
        assert_eq!(
            err,
            RebalanceError::ConsumerLeaseTransferIncomplete {
                active_leases: 2,
                transferred: 1,
            }
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_requires_reply_right_reissue() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let observed_load = ObservedCellLoad::new(256);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let mut evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 10);
        evidence.obligation_summary.active_reply_rights = 2;

        let err = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect_err("reply rights must be reissued onto the next epoch");
        assert_eq!(
            err,
            RebalanceError::ReplyRightsNotReissued {
                active_rights: 2,
                reissued: 1,
            }
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_honors_hysteresis_band() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = warm_subject_cell(&candidates, &policy);
        let err = cell
            .certify_self_rebalance(
                &policy,
                &candidates,
                ObservedCellLoad::new(512),
                RebalanceCutEvidence {
                    next_sequencer: cell.steward_set[0].clone(),
                    retention_generation: 4,
                    obligation_summary: RebalanceObligationSummary {
                        publish_obligations_below_cut: 0,
                        active_consumer_leases: 0,
                        transferred_consumer_leases: 0,
                        ambiguous_consumer_lease_owners: 0,
                        active_reply_rights: 0,
                        reissued_reply_rights: 0,
                        dangling_reply_rights: 0,
                    },
                    repair_symbols: Vec::new(),
                },
            )
            .expect_err("in-band load should not force an epoch change");
        assert_eq!(
            err,
            RebalanceError::NoRebalanceNeeded {
                cell_id: cell.cell_id,
            }
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_requires_hot_repair_spread() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = warm_subject_cell(&candidates, &policy);
        let observed_load = ObservedCellLoad::new(2_048);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let mut evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 11);
        evidence.repair_symbols =
            repair_bindings_for(&cell, &plan, &candidates, 11, plan.next_stewards.len());

        let err = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect_err("hot rebalance must prove wider repair spread");
        assert_eq!(
            err,
            RebalanceError::InsufficientRepairSymbolHolders {
                required: 6,
                actual: 4,
            }
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_rejects_wrong_symbol_epoch_binding() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let observed_load = ObservedCellLoad::new(256);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let mut evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 12);
        evidence.repair_symbols[0].cell_epoch = cell.epoch.next_generation();

        let err = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect_err("repair symbols must be bound to the certified source epoch");
        assert_eq!(
            err,
            RebalanceError::RepairBindingWrongEpoch {
                node: plan.next_stewards[0].clone(),
                expected: cell.epoch,
                actual: cell.epoch.next_generation(),
            }
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_rejects_wrong_symbol_retention_generation() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let observed_load = ObservedCellLoad::new(256);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let mut evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 13);
        evidence.repair_symbols[0].retention_generation = 99;

        let err = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect_err("repair symbols must be bound to the certified retention generation");
        assert_eq!(
            err,
            RebalanceError::RepairBindingWrongRetentionGeneration {
                node: plan.next_stewards[0].clone(),
                expected: 13,
                actual: 99,
            }
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_rejects_ineligible_repair_holder() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let observed_load = ObservedCellLoad::new(256);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let mut evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 14);
        evidence.repair_symbols[0].node_id = NodeId::new("observer-z");

        let err = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect_err("non-steward non-repair candidates must not certify the cut");
        assert_eq!(
            err,
            RebalanceError::IneligibleRepairHolder {
                node: NodeId::new("observer-z"),
            }
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_rejects_duplicate_repair_bindings() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let observed_load = ObservedCellLoad::new(256);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let mut evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 15);
        evidence
            .repair_symbols
            .push(evidence.repair_symbols[0].clone());

        let err = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect_err("duplicate repair bindings must fail closed");
        assert_eq!(
            err,
            RebalanceError::DuplicateRepairBinding {
                node: plan.next_stewards[0].clone(),
            }
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_requires_binding_for_each_next_steward() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let observed_load = ObservedCellLoad::new(256);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let missing_steward = plan.next_stewards[0].clone();
        let mut evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 16);
        evidence
            .repair_symbols
            .retain(|binding| binding.node_id != missing_steward);

        let err = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect_err("every next steward must carry a repair binding");
        assert_eq!(
            err,
            RebalanceError::MissingStewardRepairBinding {
                node: missing_steward,
            }
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_allows_retained_steward_binding_after_candidate_drop() {
        let policy = PlacementPolicy {
            cold_stewards: 1,
            warm_stewards: 3,
            hot_stewards: 3,
            candidate_pool_size: 3,
            rebalance_budget: RebalanceBudget {
                max_steward_changes: 1,
            },
            ..PlacementPolicy::default()
        };
        let all_candidates = rebalance_candidates();
        let cell = cold_subject_cell(&all_candidates, &policy);
        let current_steward = cell.steward_set[0].clone();
        let reduced_candidates: Vec<_> = all_candidates
            .into_iter()
            .filter(|candidate| candidate.node_id != current_steward)
            .collect();
        let observed_load = ObservedCellLoad::new(2_048);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &reduced_candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        assert!(
            contains_node(&plan.next_stewards, &current_steward),
            "budgeted rebalance should retain the current steward for one step"
        );

        let required_holders = cell
            .repair_policy
            .minimum_repair_holders(plan.next_temperature, plan.next_stewards.len());
        let repair_symbols =
            repair_bindings_for(&cell, &plan, &reduced_candidates, 13, required_holders);
        assert!(
            repair_symbols
                .iter()
                .any(|binding| binding.node_id == current_steward),
            "retained steward should remain eligible as a repair holder"
        );

        let evidence = RebalanceCutEvidence {
            next_sequencer: plan
                .added_stewards
                .first()
                .cloned()
                .expect("one added steward"),
            retention_generation: 13,
            obligation_summary: RebalanceObligationSummary {
                publish_obligations_below_cut: 0,
                active_consumer_leases: 0,
                transferred_consumer_leases: 0,
                ambiguous_consumer_lease_owners: 0,
                active_reply_rights: 0,
                reissued_reply_rights: 0,
                dangling_reply_rights: 0,
            },
            repair_symbols,
        };

        let certified = cell
            .certify_self_rebalance(&policy, &reduced_candidates, observed_load, evidence)
            .expect("retained stewards remain lawful repair holders during budgeted churn");
        assert!(contains_node(
            &certified.resulting_cell.steward_set,
            &current_steward
        ));
    }

    #[test]
    fn subject_cell_certified_rebalance_preserves_monotonic_fence_generation_across_epochs() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let mut cell = warm_subject_cell(&candidates, &policy);
        let second_steward = cell.steward_set[1].clone();
        let original_steward = cell.steward_set[0].clone();

        cell.control_capsule
            .fence_sequencer(second_steward)
            .expect("first fence");
        cell.control_capsule
            .fence_sequencer(original_steward)
            .expect("second fence");
        let pre_cut_generation = cell.control_capsule.sequencer_lease_generation;
        assert!(
            pre_cut_generation > cell.epoch.generation,
            "test setup must lift fence generation above the cell epoch generation"
        );

        let observed_load = ObservedCellLoad::new(2_048);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 14);

        let certified = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect("certified rebalance");
        assert_eq!(
            certified
                .resulting_cell
                .control_capsule
                .sequencer_lease_generation,
            pre_cut_generation + 1
        );
        assert!(
            certified
                .resulting_cell
                .control_capsule
                .sequencer_lease_generation
                > certified.resulting_cell.epoch.generation
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_tracks_drained_stewards_from_removed_set() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = hot_subject_cell(&candidates, &policy);
        let observed_load = ObservedCellLoad::new(32);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        assert!(
            !plan.removed_stewards.is_empty(),
            "cooling rebalance should drain at least one prior steward"
        );
        let evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 17);

        let certified = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect("certified rebalance");

        assert_eq!(certified.drained_stewards, plan.removed_stewards);
        for removed in &certified.drained_stewards {
            assert!(
                !contains_node(&certified.resulting_cell.steward_set, removed),
                "drained steward must no longer appear in the resulting stewardship set"
            );
        }
    }

    #[test]
    fn control_capsule_v1_shared_control_shard_respects_cardinality_limits() {
        let mut capsule = control_capsule();

        let shard = capsule
            .attach_shared_control_shard("control-shard-a", 1, 3)
            .expect("slot inside cardinality bound should succeed");
        assert_eq!(capsule.shared_control_shard, Some(shard));

        let err = capsule
            .attach_shared_control_shard("control-shard-a", 3, 3)
            .expect_err("out-of-range slot must fail");
        assert_eq!(
            err,
            ControlCapsuleError::SharedShardOverCapacity {
                shard_id: "control-shard-a".to_owned(),
                slot_index: 3,
                cardinality_limit: 3,
            }
        );
    }

    #[test]
    fn subject_cell_new_packs_low_rate_cells_onto_shared_control_shards() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);

        let shard = cell
            .control_capsule
            .shared_control_shard
            .as_ref()
            .expect("cold cells should pack onto a shared control shard");
        assert_eq!(
            shard.cardinality_limit,
            policy.cardinality_policy.max_cells_per_shared_shard
        );
        assert!(
            shard.slot_index < shard.cardinality_limit,
            "slot assignment must stay inside the shard cardinality limit"
        );
    }

    #[test]
    fn subject_cell_new_rejects_zero_shared_shard_cardinality_limit() {
        let candidates = rebalance_candidates();
        let policy = PlacementPolicy {
            cardinality_policy: CardinalityPolicy {
                max_cells_per_shared_shard: 0,
                ..CardinalityPolicy::default()
            },
            ..rebalance_policy()
        };

        let err = SubjectCell::new(
            &SubjectPattern::parse("orders.created").expect("pattern"),
            CellEpoch::new(11, 2),
            &candidates,
            &policy,
            RepairPolicy::default(),
            DataCapsule::default(),
        )
        .expect_err("zero-cardinality shared shard policy must fail closed");
        assert_eq!(err, FabricError::InvalidSharedShardCardinalityLimit);
    }

    #[test]
    fn subject_cell_certified_rebalance_promotes_hot_cells_to_dedicated_control_shards() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = warm_subject_cell(&candidates, &policy);
        assert!(
            cell.control_capsule.shared_control_shard.is_some(),
            "warm cells should start on a shared control shard"
        );

        let observed_load = ObservedCellLoad::new(2_048);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 15);

        let certified = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect("hot rebalance");
        assert_eq!(certified.plan.next_temperature, CellTemperature::Hot);
        assert_eq!(
            certified
                .resulting_cell
                .control_capsule
                .shared_control_shard,
            None,
            "hot cells should be promoted to dedicated control shards"
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_demotes_cooled_cells_back_to_shared_shards() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = hot_subject_cell(&candidates, &policy);
        assert_eq!(
            cell.control_capsule.shared_control_shard, None,
            "hot cells should start on dedicated control shards"
        );

        let observed_load = ObservedCellLoad::new(32);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 16);

        let certified = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect("cooled rebalance");
        assert_eq!(certified.plan.next_temperature, CellTemperature::Warm);
        assert!(
            certified
                .resulting_cell
                .control_capsule
                .shared_control_shard
                .is_some(),
            "cooled cells should demote back onto shared control shards"
        );
    }

    #[test]
    fn reply_space_compaction_packs_ephemeral_reply_subjects_onto_same_shared_shard() {
        let candidates = rebalance_candidates();
        let policy = PlacementPolicy {
            normalization: NormalizationPolicy {
                reply_space_policy: ReplySpaceCompactionPolicy {
                    enabled: true,
                    preserve_segments: 2,
                },
                ..NormalizationPolicy::default()
            },
            ..rebalance_policy()
        };
        let epoch = CellEpoch::new(17, 1);

        let first = SubjectCell::new(
            &SubjectPattern::parse("_INBOX.clientA.req-1").expect("reply subject"),
            epoch,
            &candidates,
            &policy,
            RepairPolicy::default(),
            DataCapsule::default(),
        )
        .expect("first compacted reply cell");
        let second = SubjectCell::new(
            &SubjectPattern::parse("_INBOX.clientA.req-2").expect("reply subject"),
            epoch,
            &candidates,
            &policy,
            RepairPolicy::default(),
            DataCapsule::default(),
        )
        .expect("second compacted reply cell");

        assert_eq!(
            first.subject_partition, second.subject_partition,
            "reply-space compaction should collapse ephemeral reply subjects onto one canonical partition"
        );
        assert_eq!(
            first.control_capsule.shared_control_shard, second.control_capsule.shared_control_shard,
            "compacted reply subjects should share the same control shard assignment"
        );
    }

    #[test]
    fn subject_cell_speculative_publish_confirms_without_exposing_tentative_state() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let speculative_policy = SpeculativeExecutionPolicy::default();
        let histogram = CellConflictHistogram::default();

        let attempt = cell
            .begin_speculative_publish(
                &speculative_policy,
                &histogram,
                &SpeculativePublishRequest::new(
                    "orders-confirm",
                    SemanticServiceClass::ReplyCritical,
                    "idem-orders-confirm",
                    "digest-orders-confirm",
                ),
            )
            .expect("low-conflict cell should admit speculative publish");

        assert!(
            !attempt.consumer_visible(),
            "tentative results must stay hidden until confirmation"
        );
        assert!(attempt.replay_artifact.verifies());

        let mut histogram = histogram;
        let confirmed = attempt.confirm(&mut histogram, 41);
        assert_eq!(histogram, CellConflictHistogram::new(1, 0));
        assert_eq!(confirmed.committed_obligation.control_sequence, 41);
        assert!(confirmed.consumer_visible());
        assert_eq!(
            confirmed.replay_artifact.decision,
            SpeculativeReplayDecision::Confirmed
        );
        assert!(confirmed.replay_artifact.verifies());
    }

    #[test]
    fn subject_cell_speculative_publish_aborts_conflict_and_tracks_histogram() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let speculative_policy = SpeculativeExecutionPolicy::default();
        let mut histogram = CellConflictHistogram::default();

        let attempt = cell
            .begin_speculative_publish(
                &speculative_policy,
                &histogram,
                &SpeculativePublishRequest::new(
                    "orders-conflict",
                    SemanticServiceClass::ReplyCritical,
                    "idem-orders-conflict",
                    "digest-orders-conflict",
                ),
            )
            .expect("low-conflict cell should admit speculative publish");

        let aborted = attempt.abort_due_to_conflict(
            &mut histogram,
            "cursor-conflict-7",
            "fallback-authoritative-path",
        );
        assert_eq!(histogram, CellConflictHistogram::new(1, 1));
        assert!(
            !aborted.consumer_visible(),
            "conflicted tentative results must stay hidden from consumers"
        );
        assert_eq!(aborted.corrected_outcome, "fallback-authoritative-path");
        assert_eq!(aborted.conflict_key, "cursor-conflict-7");
        assert_eq!(
            aborted.replay_artifact.decision,
            SpeculativeReplayDecision::AbortedConflict
        );
        assert!(aborted.replay_artifact.verifies());
    }

    #[test]
    fn subject_cell_speculative_publish_honors_explicit_kill_switch() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let speculative_policy =
            SpeculativeExecutionPolicy::default().with_disabled_cell(cell.cell_id);
        let histogram = CellConflictHistogram::default();

        let err = cell
            .begin_speculative_publish(
                &speculative_policy,
                &histogram,
                &SpeculativePublishRequest::new(
                    "orders-kill-switch",
                    SemanticServiceClass::ReplyCritical,
                    "idem-orders-kill-switch",
                    "digest-orders-kill-switch",
                ),
            )
            .expect_err("disabled cells must reject speculation");
        assert_eq!(
            err,
            SpeculativeExecutionError::CellKillSwitch {
                cell_id: cell.cell_id
            }
        );
    }

    #[test]
    fn subject_cell_speculative_publish_rejects_high_conflict_histogram() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let speculative_policy =
            SpeculativeExecutionPolicy::default().with_max_conflict_rate_basis_points(500);
        let histogram = CellConflictHistogram::new(20, 2);

        let err = cell
            .begin_speculative_publish(
                &speculative_policy,
                &histogram,
                &SpeculativePublishRequest::new(
                    "orders-high-conflict",
                    SemanticServiceClass::ReplyCritical,
                    "idem-orders-high-conflict",
                    "digest-orders-high-conflict",
                ),
            )
            .expect_err("conflict-heavy cells must stay off the speculative path");
        assert_eq!(
            err,
            SpeculativeExecutionError::ConflictRateTooHigh {
                cell_id: cell.cell_id,
                observed_basis_points: 1_000,
                threshold_basis_points: 500,
            }
        );
    }

    #[test]
    fn subject_cell_speculative_publish_artifacts_are_replayable_for_identical_inputs() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let speculative_policy = SpeculativeExecutionPolicy::default();
        let histogram = CellConflictHistogram::new(4, 0);
        let request = SpeculativePublishRequest::new(
            "orders-replay",
            SemanticServiceClass::ReplyCritical,
            "idem-orders-replay",
            "digest-orders-replay",
        )
        .with_delivery_class(DeliveryClass::MobilitySafe);

        let first = cell
            .begin_speculative_publish(&speculative_policy, &histogram, &request)
            .expect("first replayable attempt");
        let second = cell
            .begin_speculative_publish(&speculative_policy, &histogram, &request)
            .expect("second replayable attempt");

        assert_eq!(
            first.tentative_obligation.obligation_id,
            second.tentative_obligation.obligation_id
        );
        assert_eq!(
            first.replay_artifact.replay_key,
            second.replay_artifact.replay_key
        );
        assert_eq!(
            first.replay_artifact.oracle_key,
            second.replay_artifact.oracle_key
        );
        assert!(first.replay_artifact.verifies());
        assert!(second.replay_artifact.verifies());

        let mut histogram = histogram;
        let _ = first.confirm(&mut histogram, 7);
        let _ = second.abort_due_to_conflict(
            &mut histogram,
            "cursor-replay-cleanup",
            "fallback-replay-cleanup",
        );
    }

    #[test]
    #[cfg(debug_assertions)]
    fn subject_cell_speculative_publish_drop_without_resolution_panics_in_debug() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let speculative_policy = SpeculativeExecutionPolicy::default();
        let histogram = CellConflictHistogram::default();

        let panic = catch_unwind(AssertUnwindSafe(|| {
            let attempt = cell
                .begin_speculative_publish(
                    &speculative_policy,
                    &histogram,
                    &SpeculativePublishRequest::new(
                        "orders-drop",
                        SemanticServiceClass::ReplyCritical,
                        "idem-orders-drop",
                        "digest-orders-drop",
                    ),
                )
                .expect("low-conflict cell should admit speculative publish");
            drop(attempt);
        }));

        assert!(
            panic.is_err(),
            "unresolved speculative attempts should trip the debug drop contract"
        );
    }

    #[test]
    fn semantic_conversation_family_requires_explicit_parallel_contracts_to_split() {
        let ledger_issue = semantic_family(
            "ledger-issue",
            split_capable_kernel("ledger-issue", "ledger-issue", "publish-ledger"),
            "order:123",
            3,
        );
        let billing_notify = semantic_family(
            "billing-notify",
            split_capable_kernel("billing-notify", "billing-notify", "notify-billing"),
            "billing:invoice-123",
            1,
        );
        assert!(
            !ledger_issue.conflicts_with(&billing_notify),
            "disjoint footprints with explicit split permissions should commute"
        );

        let serial_kernel = semantic_family(
            "serial-repair",
            ProtocolKernel::new("serial-repair", DeliveryClass::DurableOrdered)
                .with_interference_class("serial-repair")
                .with_obligation_footprint("repair-ledger"),
            "repair:cell-7",
            2,
        );
        assert!(
            ledger_issue.conflicts_with(&serial_kernel),
            "families without explicit reorder/parallel contracts must fail closed"
        );

        let overlapping_state = semantic_family(
            "ledger-confirm",
            split_capable_kernel("ledger-confirm", "ledger-confirm", "confirm-ledger"),
            "order:123",
            2,
        );
        assert!(
            ledger_issue.conflicts_with(&overlapping_state),
            "shared-state overlap must keep families on the same lane"
        );
    }

    #[test]
    fn subject_cell_semantic_lane_plan_decomposes_hot_namespace_by_shared_state_footprint() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = warm_subject_cell(&candidates, &policy);

        let families = vec![
            semantic_family(
                "orders-123-authorize",
                split_capable_kernel("payments-authorize", "payments-authorize", "obligation:123"),
                "order:123",
                4,
            ),
            semantic_family(
                "orders-987-authorize",
                split_capable_kernel(
                    "payments-authorize",
                    "payments-authorize-987",
                    "obligation:987",
                ),
                "order:987",
                1,
            ),
            semantic_family(
                "orders-123-settle",
                split_capable_kernel("payments-settle", "payments-settle", "obligation:123"),
                "order:123",
                2,
            ),
        ];

        let plan = cell.plan_semantic_execution_lanes(&families);
        assert_eq!(plan.lanes.len(), 2);

        let lane_families: Vec<Vec<&str>> = plan
            .lanes
            .iter()
            .map(|lane| {
                lane.families
                    .iter()
                    .map(|family| family.family_id.as_str())
                    .collect()
            })
            .collect();
        assert_eq!(
            lane_families,
            vec![
                vec!["orders-123-authorize", "orders-123-settle"],
                vec!["orders-987-authorize"],
            ]
        );
    }

    #[test]
    fn subject_cell_semantic_lane_plan_projects_parallel_round_reduction() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);

        let families = vec![
            semantic_family(
                "inventory-rebuild",
                split_capable_kernel("inventory-rebuild", "inventory", "inventory-scan"),
                "inventory:west",
                5,
            ),
            semantic_family(
                "billing-snapshot",
                split_capable_kernel("billing-snapshot", "billing", "billing-scan"),
                "billing:east",
                4,
            ),
            semantic_family(
                "analytics-flush",
                split_capable_kernel("analytics-flush", "analytics", "analytics-flush"),
                "analytics:global",
                3,
            ),
        ];

        let first = cell.plan_semantic_execution_lanes(&families);
        let second = cell.plan_semantic_execution_lanes(&families);

        assert_eq!(first, second, "lane planning must be deterministic");
        assert_eq!(first.lanes.len(), 3);
        assert_eq!(first.serial_work_units(), 12);
        assert_eq!(first.projected_parallel_rounds(), 5);
        assert!(
            first.serial_work_units() > first.projected_parallel_rounds(),
            "independent families should reduce projected serialized rounds"
        );
    }

    #[test]
    fn recoverable_data_capsule_uses_inline_fast_path_for_tiny_payloads() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = warm_subject_cell(&candidates, &policy);
        let mut capsule = RecoverableDataCapsule::new(&cell);
        let message = FabricMessage {
            subject: Subject::parse("orders.created").expect("subject"),
            payload: b"tiny".to_vec(),
            delivery_class: DeliveryClass::DurableOrdered,
        };

        capsule
            .record_publish(&cell, &candidates, 7, &message)
            .expect("record inline segment");

        let segment = capsule.latest_segment().expect("latest segment");
        assert!(matches!(
            segment.encoding,
            DurableSegmentEncoding::Inline { .. }
        ));
        assert_eq!(segment.source_symbol_count(), 1);
        assert_eq!(segment.repair_symbol_count(), 0);
        assert_eq!(segment.holders, cell.steward_set);

        let available = cell.steward_set.iter().cloned().collect::<BTreeSet<_>>();
        let recovered = capsule
            .reconstruct_payload(7, &available)
            .expect("inline payload should be readable from a steward");
        assert_eq!(recovered, message.payload);
    }

    #[test]
    fn recoverable_data_capsule_reconstructs_coded_payload_from_partial_holders() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = hot_subject_cell(&candidates, &policy);
        let mut capsule = RecoverableDataCapsule::new(&cell);
        let payload = vec![0x5a; DEFAULT_SYMBOL_SIZE * 3];
        let message = FabricMessage {
            subject: Subject::parse("orders.created").expect("subject"),
            payload: payload.clone(),
            delivery_class: DeliveryClass::DurableOrdered,
        };

        capsule
            .record_publish(&cell, &candidates, 11, &message)
            .expect("record coded segment");

        let segment = capsule.latest_segment().expect("latest segment");
        assert!(matches!(
            segment.encoding,
            DurableSegmentEncoding::Coded { .. }
        ));
        assert!(
            segment.repair_symbol_count() >= 3,
            "hot cells should allocate extra repair symbols"
        );
        let available = segment
            .holders
            .iter()
            .take(segment.holders.len().saturating_sub(1))
            .cloned()
            .collect::<BTreeSet<_>>();
        assert!(
            !available.is_empty(),
            "test requires at least one retained holder"
        );

        let recovered = capsule
            .reconstruct_payload(11, &available)
            .expect("partial quorum should reconstruct the coded segment");
        assert_eq!(recovered, payload);
    }

    #[test]
    fn recoverable_data_capsule_detects_symbol_tampering() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = hot_subject_cell(&candidates, &policy);
        let payload = vec![0x33; DEFAULT_SYMBOL_SIZE * 2];
        let message = FabricMessage {
            subject: Subject::parse("orders.created").expect("subject"),
            payload,
            delivery_class: DeliveryClass::DurableOrdered,
        };

        let mut segment =
            DurableSegment::build(&cell, &candidates, 19, &message).expect("coded segment");
        let available = segment.holders.iter().cloned().collect::<BTreeSet<_>>();
        match &mut segment.encoding {
            DurableSegmentEncoding::Inline { .. } => panic!("expected coded segment"),
            DurableSegmentEncoding::Coded { symbols, .. } => {
                let first = symbols.first_mut().expect("stored symbol");
                first.symbol.data_mut()[0] ^= 0x01;
            }
        }

        let err = segment
            .reconstruct_payload(&available)
            .expect_err("tampered symbol must fail authentication");
        assert!(matches!(err, DataCapsuleError::AuthenticationFailed { .. }));
    }

    #[test]
    fn recoverable_data_capsule_hot_cells_plan_more_repair_than_cold_cells() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cold = cold_subject_cell(&candidates, &policy);
        let hot = hot_subject_cell(&candidates, &policy);
        let payload = vec![0xab; DEFAULT_SYMBOL_SIZE * 2];
        let message = FabricMessage {
            subject: Subject::parse("orders.created").expect("subject"),
            payload,
            delivery_class: DeliveryClass::DurableOrdered,
        };

        let cold_segment =
            DurableSegment::build(&cold, &candidates, 29, &message).expect("cold segment");
        let hot_segment =
            DurableSegment::build(&hot, &candidates, 29, &message).expect("hot segment");

        assert!(
            hot_segment.repair_symbol_count() > cold_segment.repair_symbol_count(),
            "hot cells should deepen repair spread"
        );
        assert!(
            hot_segment.holders.len() >= cold_segment.holders.len(),
            "hot cells should not reduce holder coverage"
        );
    }

    #[test]
    fn reserve_publish_durable_records_recoverable_capsule_state() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            let fabric = Fabric::connect(&cx, "node1:4222/two-phase-durable-capsule")
                .await
                .expect("connect");

            {
                let mut state = fabric.state.lock();
                state.default_data_capsule = DataCapsule {
                    temperature: CellTemperature::Hot,
                    retained_message_blocks: 3,
                };
                state.repair_policy = RepairPolicy {
                    recoverability_target: 3,
                    cold_witnesses: 1,
                    hot_witnesses: 2,
                };
                state.placement_policy.cold_stewards = 2;
                state.placement_policy.warm_stewards = 2;
                state.placement_policy.hot_stewards = 2;
                state.placement_policy.candidate_pool_size = 4;
                state.local_candidates = vec![
                    candidate("node-a", "rack-a", StorageClass::Durable, 5),
                    candidate("node-b", "rack-b", StorageClass::Durable, 6),
                    candidate("node-c", "rack-c", StorageClass::Standard, 7),
                    candidate("node-d", "rack-d", StorageClass::Standard, 8),
                ];
            }

            let mut ledger = ObligationLedger::new();
            let permit = fabric
                .reserve_publish_durable(
                    &cx,
                    &mut ledger,
                    "orders.created",
                    DeliveryClass::DurableOrdered,
                )
                .await
                .expect("durable permit");
            let payload = vec![0x44; DEFAULT_SYMBOL_SIZE * 3];
            permit.send(&cx, payload.clone());

            let state = fabric.state.lock();
            let cell = state
                .cells
                .get(&canonical_cell_key("orders.created"))
                .expect("cell runtime");
            let segment = cell
                .durable_capsule
                .latest_segment()
                .expect("durable segment recorded");
            assert!(matches!(
                segment.encoding,
                DurableSegmentEncoding::Coded { .. }
            ));
            assert!(
                cell.durable_capsule.symbol_spread.len() >= 3,
                "coded durable publish should spread symbols across stewards and witnesses"
            );

            let available = segment
                .holders
                .iter()
                .take(segment.holders.len().saturating_sub(1))
                .cloned()
                .collect::<BTreeSet<_>>();
            let recovered = cell
                .durable_capsule
                .reconstruct_payload(segment.window.start_sequence, &available)
                .expect("runtime durable capsule should reconstruct from partial holders");
            assert_eq!(recovered, payload);
        });
    }

    // ── Two-phase publish tests ───────────────────────────────────

    #[test]
    fn reserve_publish_then_send_delivers_message() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            grant_subscribe(&cx, "orders.>");
            let fabric = Fabric::connect(&cx, "node1:4222/two-phase-send")
                .await
                .expect("connect");
            let mut sub = fabric.subscribe(&cx, "orders.>").await.expect("subscribe");

            let permit = fabric
                .reserve_publish(&cx, "orders.created", DeliveryClass::EphemeralInteractive)
                .await
                .expect("reserve");

            assert_eq!(permit.subject().as_str(), "orders.created");
            assert_eq!(permit.delivery_class(), DeliveryClass::EphemeralInteractive);
            assert!(permit.obligation_id().is_none());

            let receipt = permit.send(&cx, b"hello".to_vec());
            assert_eq!(receipt.payload_len, 5);
            assert_eq!(receipt.ack_kind, AckKind::Accepted);
            assert_eq!(receipt.delivery_class, DeliveryClass::EphemeralInteractive);

            let msg = sub.next(&cx).await.expect("message");
            assert_eq!(msg.subject.as_str(), "orders.created");
            assert_eq!(msg.payload, b"hello".to_vec());
        });
    }

    #[test]
    fn reserve_publish_then_abort_delivers_nothing() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.>");
            grant_subscribe(&cx, "orders.>");
            let fabric = Fabric::connect(&cx, "node1:4222/two-phase-abort")
                .await
                .expect("connect");
            let mut sub = fabric.subscribe(&cx, "orders.>").await.expect("subscribe");

            let permit = fabric
                .reserve_publish(&cx, "orders.created", DeliveryClass::EphemeralInteractive)
                .await
                .expect("reserve");
            permit.abort(&cx);

            // Publish a second message to verify the first was not delivered.
            let _ = fabric
                .publish(&cx, "orders.other", b"after-abort".to_vec())
                .await
                .expect("publish after abort");

            let msg = sub.next(&cx).await.expect("message");
            assert_eq!(
                msg.subject.as_str(),
                "orders.other",
                "aborted permit must not deliver its message"
            );
        });
    }

    #[test]
    fn reserve_publish_holds_cell_capacity_until_abort() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            let fabric = Fabric::connect(&cx, "node1:4222/two-phase-capacity-abort")
                .await
                .expect("connect");
            fabric.state.lock().cell_buffer_capacity = 1;

            let permit = fabric
                .reserve_publish(&cx, "orders.created", DeliveryClass::EphemeralInteractive)
                .await
                .expect("reserve");

            let err = fabric
                .reserve_publish(&cx, "orders.created", DeliveryClass::EphemeralInteractive)
                .await
                .expect_err("outstanding permit should hold cell capacity");
            assert_eq!(err.kind(), ErrorKind::ChannelFull);

            let cell_key = canonical_cell_key("orders.created");
            {
                let state = fabric.state.lock();
                let cell = state.cells.get(&cell_key).expect("cell runtime");
                assert_eq!(cell.buffer.len(), 0);
                assert_eq!(cell.reserved_slots, 1);
                assert_eq!(cell.state, FabricCellBufferState::Backpressured);
            }

            permit.abort(&cx);

            {
                let state = fabric.state.lock();
                let cell = state.cells.get(&cell_key).expect("cell runtime");
                assert_eq!(cell.buffer.len(), 0);
                assert_eq!(cell.reserved_slots, 0);
                assert_eq!(cell.state, FabricCellBufferState::Empty);
            }

            let _permit = fabric
                .reserve_publish(&cx, "orders.created", DeliveryClass::EphemeralInteractive)
                .await
                .expect("abort should release reserved capacity");
        });
    }

    #[test]
    fn reserve_publish_drop_delivers_nothing() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.>");
            grant_subscribe(&cx, "orders.>");
            let fabric = Fabric::connect(&cx, "node1:4222/two-phase-drop")
                .await
                .expect("connect");
            let mut sub = fabric.subscribe(&cx, "orders.>").await.expect("subscribe");

            {
                let _permit = fabric
                    .reserve_publish(&cx, "orders.created", DeliveryClass::EphemeralInteractive)
                    .await
                    .expect("reserve");
                // permit dropped without send or abort
            }

            let _ = fabric
                .publish(&cx, "orders.other", b"after-drop".to_vec())
                .await
                .expect("publish after drop");

            let msg = sub.next(&cx).await.expect("message");
            assert_eq!(
                msg.subject.as_str(),
                "orders.other",
                "dropped permit must not deliver its message"
            );
        });
    }

    #[test]
    fn reserve_publish_drop_releases_reserved_capacity() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            let fabric = Fabric::connect(&cx, "node1:4222/two-phase-capacity-drop")
                .await
                .expect("connect");
            fabric.state.lock().cell_buffer_capacity = 1;

            {
                let _permit = fabric
                    .reserve_publish(&cx, "orders.created", DeliveryClass::EphemeralInteractive)
                    .await
                    .expect("reserve");

                let err = fabric
                    .reserve_publish(&cx, "orders.created", DeliveryClass::EphemeralInteractive)
                    .await
                    .expect_err("outstanding permit should hold cell capacity");
                assert_eq!(err.kind(), ErrorKind::ChannelFull);
            }

            let cell_key = canonical_cell_key("orders.created");
            {
                let state = fabric.state.lock();
                let cell = state.cells.get(&cell_key).expect("cell runtime");
                assert_eq!(cell.buffer.len(), 0);
                assert_eq!(cell.reserved_slots, 0);
                assert_eq!(cell.state, FabricCellBufferState::Empty);
            }

            let _permit = fabric
                .reserve_publish(&cx, "orders.created", DeliveryClass::EphemeralInteractive)
                .await
                .expect("drop should release reserved capacity");
        });
    }

    #[test]
    fn reserve_publish_durable_allocates_obligation() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            let fabric = Fabric::connect(&cx, "node1:4222/two-phase-durable")
                .await
                .expect("connect");
            let mut ledger = ObligationLedger::new();

            let permit = fabric
                .reserve_publish_durable(
                    &cx,
                    &mut ledger,
                    "orders.created",
                    DeliveryClass::DurableOrdered,
                )
                .await
                .expect("reserve durable");

            let obligation_id = permit
                .obligation_id()
                .expect("durable publish must allocate obligation");
            assert_eq!(permit.delivery_class(), DeliveryClass::DurableOrdered);

            let receipt = permit.send(&cx, b"durable-payload".to_vec());
            assert_eq!(receipt.ack_kind, AckKind::Recoverable);
            assert_eq!(receipt.delivery_class, DeliveryClass::DurableOrdered);
            assert_eq!(ledger.pending_count(), 0);
            assert_eq!(ledger.stats().total_committed, 1);
            assert_eq!(
                ledger
                    .get(obligation_id)
                    .expect("committed obligation must remain recorded")
                    .state,
                crate::record::ObligationState::Committed
            );
        });
    }

    #[test]
    fn reserve_publish_durable_abort_resolves_obligation() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            let fabric = Fabric::connect(&cx, "node1:4222/two-phase-durable-abort")
                .await
                .expect("connect");
            let mut ledger = ObligationLedger::new();

            let permit = fabric
                .reserve_publish_durable(
                    &cx,
                    &mut ledger,
                    "orders.created",
                    DeliveryClass::DurableOrdered,
                )
                .await
                .expect("reserve durable");
            let obligation_id = permit
                .obligation_id()
                .expect("durable publish must allocate obligation");

            permit.abort(&cx);

            assert_eq!(ledger.pending_count(), 0);
            assert_eq!(ledger.stats().total_aborted, 1);
            assert_eq!(
                ledger
                    .get(obligation_id)
                    .expect("aborted obligation must remain recorded")
                    .state,
                crate::record::ObligationState::Aborted
            );
        });
    }

    #[test]
    fn reserve_publish_durable_drop_resolves_obligation() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            let fabric = Fabric::connect(&cx, "node1:4222/two-phase-durable-drop")
                .await
                .expect("connect");
            let mut ledger = ObligationLedger::new();
            let obligation_id;

            {
                let permit = fabric
                    .reserve_publish_durable(
                        &cx,
                        &mut ledger,
                        "orders.created",
                        DeliveryClass::DurableOrdered,
                    )
                    .await
                    .expect("reserve durable");
                obligation_id = permit
                    .obligation_id()
                    .expect("durable publish must allocate obligation");
            }

            assert_eq!(ledger.pending_count(), 0);
            assert_eq!(ledger.stats().total_aborted, 1);
            assert_eq!(
                ledger
                    .get(obligation_id)
                    .expect("dropped obligation must remain recorded")
                    .state,
                crate::record::ObligationState::Aborted
            );
        });
    }

    #[test]
    fn reserve_publish_rejects_durable_ordered_without_ledger() {
        run_test_with_cx(|cx| async move {
            let fabric = Fabric::connect(&cx, "node1:4222/two-phase-plain-durable")
                .await
                .expect("connect");

            let err = fabric
                .reserve_publish(&cx, "orders.created", DeliveryClass::DurableOrdered)
                .await
                .expect_err("durable ordered publish without ledger must fail");

            assert!(
                err.to_string().contains("reserve_publish_durable"),
                "expected ledger guidance in error, got {err}"
            );
        });
    }

    #[test]
    fn reserve_publish_durable_rejects_ephemeral_interactive() {
        run_test_with_cx(|cx| async move {
            let fabric = Fabric::connect(&cx, "node1:4222/two-phase-ephemeral-durable")
                .await
                .expect("connect");
            let mut ledger = ObligationLedger::new();

            let err = fabric
                .reserve_publish_durable(
                    &cx,
                    &mut ledger,
                    "orders.created",
                    DeliveryClass::EphemeralInteractive,
                )
                .await
                .expect_err("ephemeral publish should stay on reserve_publish");

            assert!(
                err.to_string().contains("reserve_publish"),
                "expected plain-publish guidance, got {err}"
            );
            assert_eq!(ledger.pending_count(), 0);
        });
    }

    #[test]
    fn reserve_publish_durable_rejects_higher_layer_delivery_classes() {
        run_test_with_cx(|cx| async move {
            let fabric = Fabric::connect(&cx, "node1:4222/two-phase-unsupported-class")
                .await
                .expect("connect");
            let mut ledger = ObligationLedger::new();

            let err = fabric
                .reserve_publish_durable(
                    &cx,
                    &mut ledger,
                    "orders.created",
                    DeliveryClass::ObligationBacked,
                )
                .await
                .expect_err("packet-plane publish must reject higher-layer delivery classes");

            assert!(
                err.to_string()
                    .contains("does not yet support delivery class"),
                "expected unsupported-class guidance, got {err}"
            );
            assert_eq!(ledger.pending_count(), 0);
        });
    }

    #[test]
    fn reserve_publish_requires_matching_publish_capability() {
        run_test_with_cx(|cx| async move {
            let fabric = Fabric::connect(&cx, "node1:4222/deny-reserve")
                .await
                .expect("connect");

            let err = fabric
                .reserve_publish(&cx, "orders.created", DeliveryClass::EphemeralInteractive)
                .await
                .expect_err("reserve without publish capability must fail");

            assert_eq!(err.kind(), ErrorKind::AdmissionDenied);
            let decisions = fabric
                .decision_records()
                .into_iter()
                .filter(|record| record.contract_name() == "fabric_capability_decision")
                .collect::<Vec<_>>();
            assert_eq!(decisions.len(), 1);
            assert_eq!(decisions[0].audit.action_chosen, "reject");
        });
    }

    #[test]
    fn subscribe_requires_matching_subscribe_capability() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            let fabric = Fabric::connect(&cx, "node1:4222/deny-subscribe")
                .await
                .expect("connect");

            let err = fabric
                .subscribe(&cx, "orders.>")
                .await
                .expect_err("subscribe without subscribe capability must fail");

            assert_eq!(err.kind(), ErrorKind::AdmissionDenied);
            let decisions = fabric
                .decision_records()
                .into_iter()
                .filter(|record| record.contract_name() == "fabric_capability_decision")
                .collect::<Vec<_>>();
            assert_eq!(decisions.len(), 1);
            assert_eq!(decisions[0].audit.action_chosen, "reject");
        });
    }

    #[test]
    fn request_requires_subscribe_capability_even_with_publish_granted() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "service.lookup");
            let fabric = Fabric::connect(&cx, "node1:4222/deny-request")
                .await
                .expect("connect");

            let err = fabric
                .request(&cx, "service.lookup", b"lookup".to_vec())
                .await
                .expect_err("request without subscribe capability must fail");

            assert_eq!(err.kind(), ErrorKind::AdmissionDenied);
            let decisions = fabric
                .decision_records()
                .into_iter()
                .filter(|record| record.contract_name() == "fabric_capability_decision")
                .collect::<Vec<_>>();
            assert_eq!(decisions.len(), 1);
            assert_eq!(decisions[0].audit.action_chosen, "reject");
        });
    }

    #[test]
    fn certified_request_requires_publish_and_subscribe_capabilities() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "service.lookup");
            let fabric = Fabric::connect(&cx, "node1:4222/deny-certified")
                .await
                .expect("connect");
            let mut ledger = ObligationLedger::new();
            let admission = service_admission(
                "req-certified-denied",
                "service.lookup",
                DeliveryClass::ObligationBacked,
                Some(Duration::from_secs(5)),
                cx.now(),
            );

            let err = fabric
                .request_certified(
                    &cx,
                    &mut ledger,
                    &admission,
                    "callee-a",
                    b"lookup".to_vec(),
                    AckKind::Received,
                    true,
                )
                .await
                .expect_err("certified request without subscribe capability must fail");

            assert_eq!(err.kind(), ErrorKind::AdmissionDenied);
            let decisions = fabric
                .decision_records()
                .into_iter()
                .filter(|record| record.contract_name() == "fabric_capability_decision")
                .collect::<Vec<_>>();
            assert_eq!(decisions.len(), 2);
            assert_eq!(decisions[0].audit.action_chosen, "allow");
            assert_eq!(decisions[1].audit.action_chosen, "reject");
        });
    }

    #[test]
    fn publish_convenience_wrapper_works() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "events.fired");
            grant_subscribe(&cx, "events.>");
            let fabric = Fabric::connect(&cx, "node1:4222/publish-wrapper")
                .await
                .expect("connect");
            let mut sub = fabric.subscribe(&cx, "events.>").await.expect("subscribe");

            let receipt = fabric
                .publish(&cx, "events.fired", b"wrapper".to_vec())
                .await
                .expect("publish via wrapper");

            assert_eq!(receipt.ack_kind, AckKind::Accepted);
            assert_eq!(receipt.delivery_class, DeliveryClass::EphemeralInteractive);

            let msg = sub.next(&cx).await.expect("message");
            assert_eq!(msg.subject.as_str(), "events.fired");
            assert_eq!(msg.payload, b"wrapper".to_vec());
        });
    }
