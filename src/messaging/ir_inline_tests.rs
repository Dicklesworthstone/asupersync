    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[allow(clippy::too_many_lines)]
    fn sample_fabric_ir() -> FabricIr {
        FabricIr {
            schema_version: FABRIC_IR_SCHEMA_VERSION,
            subjects: vec![
                SubjectSchema {
                    pattern: SubjectPattern::new("tenant.orders.command"),
                    family: SubjectFamily::Command,
                    delivery_class: DeliveryClass::ObligationBacked,
                    evidence_policy: EvidencePolicy {
                        sampling_ratio: 1.0,
                        retention: RetentionPolicy::RetainForEvents { events: 64 },
                        record_payload_hashes: true,
                        record_control_transitions: true,
                        record_counterfactual_branches: true,
                    },
                    privacy_policy: PrivacyPolicy {
                        name: "orders-subject".to_owned(),
                        metadata_disclosure: MetadataDisclosure::Hashed,
                        redact_subject_literals: false,
                        noise_budget: Some(0.5),
                        allow_cross_tenant_flow: false,
                    },
                    reply_space: Some(ReplySpaceRule::DedicatedPrefix {
                        prefix: "_INBOX.orders".to_owned(),
                    }),
                    mobility: MobilityPermission::Federated,
                    quantitative_obligation: Some(QuantitativeObligationContract {
                        name: "orders-command-slo".to_owned(),
                        class: DeliveryClass::ObligationBacked,
                        target_latency: Duration::from_millis(150),
                        target_probability: 0.995,
                        retry_law: RetryLaw::Fixed {
                            max_retries: 3,
                            delay: Duration::from_millis(10),
                        },
                        degradation_policy: DegradationPolicy::DowngradeTo {
                            class: DeliveryClass::DurableOrdered,
                        },
                    }),
                },
                SubjectSchema {
                    pattern: SubjectPattern::new("$SYS.health.*"),
                    family: SubjectFamily::Control,
                    delivery_class: DeliveryClass::DurableOrdered,
                    evidence_policy: EvidencePolicy::default(),
                    privacy_policy: PrivacyPolicy::default(),
                    reply_space: None,
                    mobility: MobilityPermission::LocalOnly,
                    quantitative_obligation: None,
                },
                SubjectSchema {
                    pattern: SubjectPattern::new("tenant.capture.>"),
                    family: SubjectFamily::CaptureSelector,
                    delivery_class: DeliveryClass::EphemeralInteractive,
                    evidence_policy: EvidencePolicy::default(),
                    privacy_policy: PrivacyPolicy::default(),
                    reply_space: None,
                    mobility: MobilityPermission::Federated,
                    quantitative_obligation: None,
                },
            ],
            morphisms: vec![MorphismPlan {
                name: "orders-to-audit".to_owned(),
                source_pattern: SubjectPattern::new("tenant.orders.>"),
                target_prefix: "audit.orders".to_owned(),
                allowed_families: vec![SubjectFamily::Event, SubjectFamily::Command],
                transforms: vec![
                    MorphismTransform::RenamePrefix {
                        from: "tenant.orders".to_owned(),
                        to: "audit.orders".to_owned(),
                    },
                    MorphismTransform::PreserveReplySpace,
                    MorphismTransform::EscalateDeliveryClass {
                        class: DeliveryClass::ForensicReplayable,
                    },
                ],
            }],
            services: vec![ServiceContract {
                name: "orders.lookup".to_owned(),
                operations: vec![ServiceOperation {
                    name: "lookup".to_owned(),
                    request: SubjectPattern::new("service.orders.lookup"),
                    reply_space: Some(ReplySpaceRule::CallerInbox),
                    delivery_class: DeliveryClass::ObligationBacked,
                    idempotent: true,
                }],
                default_consumer_policy: ConsumerPolicy {
                    name: "orders-default".to_owned(),
                    mode: ConsumerMode::Replayable,
                    delivery_class: DeliveryClass::ObligationBacked,
                    ack_kind: AckKind::Served,
                    max_pending: 1024,
                    max_deliver: 4,
                    replay_window: Some(Duration::from_secs(30)),
                },
                required_capability: Some("fabric.orders.read".to_owned()),
                quantitative_obligation: Some(QuantitativeObligationContract {
                    name: "orders-service-slo".to_owned(),
                    class: DeliveryClass::ObligationBacked,
                    target_latency: Duration::from_millis(200),
                    target_probability: 0.99,
                    retry_law: RetryLaw::Exponential {
                        max_retries: 5,
                        base_delay: Duration::from_millis(10),
                        max_delay: Duration::from_millis(250),
                    },
                    degradation_policy: DegradationPolicy::ShedLoad,
                }),
            }],
            protocols: vec![ProtocolContract {
                name: "orders.checkout".to_owned(),
                roles: vec![
                    "client".to_owned(),
                    "inventory".to_owned(),
                    "billing".to_owned(),
                ],
                entry_subject: SubjectPattern::new("protocol.checkout.begin"),
                session: SessionSchema {
                    name: "checkout-session".to_owned(),
                    steps: vec![
                        SessionStep::Send {
                            role: "client".to_owned(),
                            subject: SubjectPattern::new("protocol.checkout.begin"),
                        },
                        SessionStep::Choice {
                            decider_role: "inventory".to_owned(),
                            branches: vec![
                                SessionBranch {
                                    label: "reserved".to_owned(),
                                    steps: vec![
                                        SessionStep::Receive {
                                            role: "billing".to_owned(),
                                            subject: SubjectPattern::new(
                                                "protocol.checkout.billing",
                                            ),
                                        },
                                        SessionStep::End,
                                    ],
                                },
                                SessionBranch {
                                    label: "rejected".to_owned(),
                                    steps: vec![SessionStep::End],
                                },
                            ],
                        },
                        SessionStep::End,
                    ],
                },
                branch_policy: BranchPolicy {
                    name: "orders-audit".to_owned(),
                    attachment: BranchAttachment::AuditedAnalyst,
                    mutation_mode: BranchMutationMode::ReadOnly,
                    retention: RetentionPolicy::RetainFor {
                        duration: Duration::from_secs(60),
                    },
                },
            }],
            consumers: vec![ConsumerPolicy {
                name: "orders-replay".to_owned(),
                mode: ConsumerMode::Replayable,
                delivery_class: DeliveryClass::DurableOrdered,
                ack_kind: AckKind::Recoverable,
                max_pending: 512,
                max_deliver: 8,
                replay_window: Some(Duration::from_secs(300)),
            }],
            privacy_policies: vec![PrivacyPolicy {
                name: "tenant-safe".to_owned(),
                metadata_disclosure: MetadataDisclosure::Hashed,
                redact_subject_literals: true,
                noise_budget: Some(0.25),
                allow_cross_tenant_flow: false,
            }],
            cut_policies: vec![CutPolicy {
                name: "evidence-budget".to_owned(),
                trigger: CutTrigger::AtEvidenceBudgetBytes { bytes: 4096 },
                retention: RetentionPolicy::RetainForEvents { events: 16 },
                materialization: MaterializationPolicy::ControlPlaneOnly,
            }],
            branch_policies: vec![BranchPolicy {
                name: "analyst-read-only".to_owned(),
                attachment: BranchAttachment::AuditedAnalyst,
                mutation_mode: BranchMutationMode::ReadOnly,
                retention: RetentionPolicy::RetainFor {
                    duration: Duration::from_secs(60),
                },
            }],
            obligation_contracts: vec![QuantitativeObligationContract {
                name: "orders-p99".to_owned(),
                class: DeliveryClass::ObligationBacked,
                target_latency: Duration::from_millis(150),
                target_probability: 0.995,
                retry_law: RetryLaw::Fixed {
                    max_retries: 3,
                    delay: Duration::from_millis(10),
                },
                degradation_policy: DegradationPolicy::DowngradeTo {
                    class: DeliveryClass::DurableOrdered,
                },
            }],
            capability_tokens: vec![CapabilityTokenSchema {
                name: "fabric.orders.read".to_owned(),
                families: vec![SubjectFamily::Command, SubjectFamily::Reply],
                delivery_classes: vec![
                    DeliveryClass::DurableOrdered,
                    DeliveryClass::ObligationBacked,
                ],
                permissions: vec![CapabilityPermission::Request, CapabilityPermission::Reply],
            }],
        }
    }

    #[test]
    fn default_construction_produces_a_valid_empty_document() {
        let ir = FabricIr::default();
        assert!(
            ir.validate().is_empty(),
            "default IR should be valid: {ir:?}"
        );
    }

    #[test]
    fn fabric_ir_round_trips_through_serde() {
        let ir = sample_fabric_ir();
        let json = serde_json::to_string_pretty(&ir).expect("serialize FABRIC IR");
        let decoded: FabricIr = serde_json::from_str(&json).expect("deserialize FABRIC IR");
        assert_eq!(decoded, ir);
    }

    #[test]
    fn latency_estimate_new_normalizes_monotone_order() {
        let estimate = LatencyEstimate::new(
            Duration::from_millis(10),
            Duration::from_millis(5),
            Duration::from_millis(1),
        );

        assert_eq!(
            estimate,
            LatencyEstimate {
                median: Duration::from_millis(10),
                p99: Duration::from_millis(10),
                p999: Duration::from_millis(10),
            }
        );
    }

    #[test]
    fn cpu_estimate_new_normalizes_monotone_order() {
        let estimate = CpuEstimate::new(12, 4);

        assert_eq!(
            estimate,
            CpuEstimate {
                typical_micros: 12,
                p99_micros: 12,
            }
        );
    }

    #[test]
    fn byte_estimate_new_normalizes_monotone_order() {
        let estimate = ByteEstimate::new(100, 50, 25);

        assert_eq!(
            estimate,
            ByteEstimate {
                min_bytes: 100,
                typical_bytes: 100,
                max_bytes: 100,
            }
        );
    }

    #[test]
    fn duration_estimate_new_normalizes_monotone_order() {
        let estimate = DurationEstimate::new(
            Duration::from_millis(10),
            Duration::from_millis(5),
            Duration::from_millis(1),
        );

        assert_eq!(
            estimate,
            DurationEstimate {
                min: Duration::from_millis(10),
                typical: Duration::from_millis(10),
                max: Duration::from_millis(10),
            }
        );
    }

    #[test]
    fn estimate_constructors_only_raise_inverted_fields() {
        assert_eq!(
            LatencyEstimate::new(
                Duration::from_millis(10),
                Duration::from_millis(15),
                Duration::from_millis(12),
            ),
            LatencyEstimate {
                median: Duration::from_millis(10),
                p99: Duration::from_millis(15),
                p999: Duration::from_millis(15),
            }
        );
        assert_eq!(
            CpuEstimate::new(12, 20),
            CpuEstimate {
                typical_micros: 12,
                p99_micros: 20,
            }
        );
        assert_eq!(
            ByteEstimate::new(10, 5, 30),
            ByteEstimate {
                min_bytes: 10,
                typical_bytes: 10,
                max_bytes: 30,
            }
        );
        assert_eq!(
            DurationEstimate::new(
                Duration::from_millis(10),
                Duration::from_millis(12),
                Duration::from_millis(11),
            ),
            DurationEstimate {
                min: Duration::from_millis(10),
                typical: Duration::from_millis(12),
                max: Duration::from_millis(12),
            }
        );
    }

    #[test]
    fn estimate_deserialization_normalizes_monotone_order() {
        let latency: LatencyEstimate = serde_json::from_value(serde_json::json!({
            "median": serde_json::to_value(Duration::from_millis(10)).expect("serialize duration"),
            "p99": serde_json::to_value(Duration::from_millis(5)).expect("serialize duration"),
            "p999": serde_json::to_value(Duration::from_millis(1)).expect("serialize duration"),
        }))
        .expect("deserialize latency estimate");
        assert_eq!(
            latency,
            LatencyEstimate {
                median: Duration::from_millis(10),
                p99: Duration::from_millis(10),
                p999: Duration::from_millis(10),
            }
        );

        let cpu: CpuEstimate = serde_json::from_value(serde_json::json!({
            "typical_micros": 12,
            "p99_micros": 4,
        }))
        .expect("deserialize cpu estimate");
        assert_eq!(
            cpu,
            CpuEstimate {
                typical_micros: 12,
                p99_micros: 12,
            }
        );

        let bytes: ByteEstimate = serde_json::from_value(serde_json::json!({
            "min_bytes": 100,
            "typical_bytes": 50,
            "max_bytes": 25,
        }))
        .expect("deserialize byte estimate");
        assert_eq!(
            bytes,
            ByteEstimate {
                min_bytes: 100,
                typical_bytes: 100,
                max_bytes: 100,
            }
        );

        let duration: DurationEstimate = serde_json::from_value(serde_json::json!({
            "min": serde_json::to_value(Duration::from_millis(10)).expect("serialize duration"),
            "typical": serde_json::to_value(Duration::from_millis(5)).expect("serialize duration"),
            "max": serde_json::to_value(Duration::from_millis(1)).expect("serialize duration"),
        }))
        .expect("deserialize duration estimate");
        assert_eq!(
            duration,
            DurationEstimate {
                min: Duration::from_millis(10),
                typical: Duration::from_millis(10),
                max: Duration::from_millis(10),
            }
        );
    }

    #[test]
    fn enum_coverage_stays_exhaustive_for_core_fieldless_enums() {
        assert_eq!(SubjectFamily::ALL.len(), 7);
        assert!(SubjectFamily::ALL.contains(&SubjectFamily::ProtocolStep));

        assert_eq!(MobilityPermission::ALL.len(), 3);
        assert!(MobilityPermission::ALL.contains(&MobilityPermission::StewardshipTransfer));

        assert_eq!(ConsumerMode::ALL.len(), 3);
        assert!(ConsumerMode::ALL.contains(&ConsumerMode::Replayable));

        assert_eq!(MetadataDisclosure::ALL.len(), 3);
        assert!(MetadataDisclosure::ALL.contains(&MetadataDisclosure::Redacted));

        assert_eq!(MaterializationPolicy::ALL.len(), 3);
        assert!(MaterializationPolicy::ALL.contains(&MaterializationPolicy::FullReplayable));

        assert_eq!(BranchAttachment::ALL.len(), 3);
        assert!(BranchAttachment::ALL.contains(&BranchAttachment::AuditedAnalyst));

        assert_eq!(BranchMutationMode::ALL.len(), 2);
        assert!(BranchMutationMode::ALL.contains(&BranchMutationMode::SandboxedMutation));

        assert_eq!(CapabilityPermission::ALL.len(), 5);
        assert!(CapabilityPermission::ALL.contains(&CapabilityPermission::BranchAttach));
    }

    #[test]
    fn tagged_variant_enums_serialize_every_variant_shape() {
        for value in [
            serde_json::to_value(ReplySpaceRule::CallerInbox).expect("serialize caller inbox"),
            serde_json::to_value(ReplySpaceRule::SharedPrefix {
                prefix: "_INBOX.shared".to_owned(),
            })
            .expect("serialize shared prefix"),
            serde_json::to_value(ReplySpaceRule::DedicatedPrefix {
                prefix: "_INBOX.dedicated".to_owned(),
            })
            .expect("serialize dedicated prefix"),
            serde_json::to_value(MorphismTransform::PreserveReplySpace)
                .expect("serialize morphism preserve"),
            serde_json::to_value(MorphismTransform::RenamePrefix {
                from: "a".to_owned(),
                to: "b".to_owned(),
            })
            .expect("serialize morphism rename"),
            serde_json::to_value(CutTrigger::Manual).expect("serialize cut manual"),
            serde_json::to_value(CutTrigger::AtEvidenceBudgetBytes { bytes: 1 })
                .expect("serialize cut budget"),
            serde_json::to_value(RetryLaw::Never).expect("serialize retry never"),
            serde_json::to_value(RetryLaw::Fixed {
                max_retries: 1,
                delay: Duration::from_millis(1),
            })
            .expect("serialize retry fixed"),
            serde_json::to_value(DegradationPolicy::FailClosed)
                .expect("serialize degrade fail closed"),
            serde_json::to_value(DegradationPolicy::DowngradeTo {
                class: DeliveryClass::DurableOrdered,
            })
            .expect("serialize degrade downgrade"),
            serde_json::to_value(SessionStep::End).expect("serialize session end"),
            serde_json::to_value(SessionStep::Send {
                role: "caller".to_owned(),
                subject: SubjectPattern::new("fabric.test"),
            })
            .expect("serialize session send"),
        ] {
            assert!(
                value.get("kind").is_some(),
                "expected tagged enum payload: {value}"
            );
        }
    }

    #[test]
    fn cut_policy_is_constructible_and_validates() {
        let cut = CutPolicy {
            name: "periodic-cut".to_owned(),
            trigger: CutTrigger::Every {
                interval: Duration::from_secs(5),
            },
            retention: RetentionPolicy::RetainForEvents { events: 32 },
            materialization: MaterializationPolicy::ControlPlaneOnly,
        };

        let value = serde_json::to_value(&cut).expect("serialize cut policy");
        assert_eq!(value["trigger"]["kind"], "every");

        let mut errors = Vec::new();
        cut.validate_at("cut_policy", &mut errors);
        assert!(
            errors.is_empty(),
            "expected valid cut policy, got {errors:?}"
        );
    }

    #[test]
    fn validation_rejects_invalid_configurations() {
        let mut ir = sample_fabric_ir();
        ir.subjects[0].reply_space = None;
        ir.subjects[1].pattern = SubjectPattern::new("control.health");
        ir.subjects[2].pattern = SubjectPattern::new("tenant.capture.literal");
        ir.morphisms[0].transforms = Vec::new();
        ir.services[0].default_consumer_policy.ack_kind = AckKind::Accepted;
        ir.services[0].default_consumer_policy.replay_window = None;
        ir.protocols[0].roles = vec!["client".to_owned(), "client".to_owned()];
        ir.capability_tokens[0].delivery_classes = Vec::new();
        ir.capability_tokens[0].permissions = Vec::new();
        ir.subjects[0].quantitative_obligation = Some(QuantitativeObligationContract {
            name: "subject-slo".to_owned(),
            class: DeliveryClass::DurableOrdered,
            target_latency: Duration::ZERO,
            target_probability: 2.0,
            retry_law: RetryLaw::Exponential {
                max_retries: 0,
                base_delay: Duration::ZERO,
                max_delay: Duration::from_millis(1),
            },
            degradation_policy: DegradationPolicy::DowngradeTo {
                class: DeliveryClass::ForensicReplayable,
            },
        });

        let errors = ir.validate();
        let messages = errors
            .iter()
            .map(|error| format!("{} => {}", error.field, error.message))
            .collect::<Vec<_>>();

        assert!(
            messages
                .iter()
                .any(|message| message.contains("command subjects must declare a reply-space rule"))
        );
        assert!(
            messages
                .iter()
                .any(|message| message
                    .contains("control subjects must live under `$SYS.` or `sys.`"))
        );
        assert!(
            messages.iter().any(
                |message| message.contains("capture-selector subjects must include `*` or `>`")
            )
        );
        assert!(messages.iter().any(|message| {
            message.contains("morphism plan must declare at least one transform step")
        }));
        assert!(messages.iter().any(|message| {
            message.contains("weaker than the minimum") || message.contains("replayable consumers")
        }));
        assert!(
            messages
                .iter()
                .any(|message| message.contains("protocol role names must be unique and non-empty"))
        );
        assert!(messages.iter().any(|message| {
            message.contains("capability token schema must authorize at least one delivery class")
        }));
        assert!(messages.iter().any(|message| {
            message.contains("capability token schema must authorize at least one permission")
        }));
        assert!(messages.iter().any(|message| {
            message.contains("quantitative obligation class must match the subject delivery class")
        }));
        assert!(messages.iter().any(|message| {
            message.contains("quantitative target latency must be greater than zero")
        }));
        assert!(
            messages
                .iter()
                .any(|message| message.contains("quantitative target probability must be"))
        );
        assert!(messages.iter().any(|message| {
            message.contains("exponential retry law must allow at least one retry")
                || message.contains("exponential retry base delay must be greater than zero")
        }));
        assert!(
            messages.iter().any(|message| {
                message.contains(
                    "degradation downgrade target must be strictly weaker than the baseline delivery class",
                )
            })
        );
    }

    #[test]
    fn validation_rejects_service_capabilities_missing_from_ir_declarations() {
        let mut ir = sample_fabric_ir();
        ir.services[0].required_capability = Some("fabric.orders.admin".to_owned());

        let errors = ir.validate();
        let messages = error_messages(&errors);

        assert!(
            messages.iter().any(|message| {
                message.contains("services[0].required_capability")
                    && message.contains("fabric.orders.admin")
                    && message.contains("is not declared in capability_tokens")
            }),
            "expected missing-capability validation error, got {messages:?}"
        );
    }

    #[test]
    fn validation_rejects_protocol_session_roles_not_declared_by_the_contract() {
        let mut ir = sample_fabric_ir();
        ir.protocols[0].session.steps = vec![
            SessionStep::Send {
                role: "shipper".to_owned(),
                subject: SubjectPattern::new("protocol.checkout.begin"),
            },
            SessionStep::Choice {
                decider_role: "approver".to_owned(),
                branches: vec![SessionBranch {
                    label: "approved".to_owned(),
                    steps: vec![
                        SessionStep::Receive {
                            role: "auditor".to_owned(),
                            subject: SubjectPattern::new("protocol.checkout.audit"),
                        },
                        SessionStep::End,
                    ],
                }],
            },
            SessionStep::End,
        ];

        let errors = ir.validate();
        let messages = error_messages(&errors);

        assert!(
            messages.iter().any(|message| {
                message.contains("protocols[0].session.steps[0].role")
                    && message.contains("shipper")
                    && message.contains("is not declared by the protocol contract")
            }),
            "expected undeclared send-role validation error, got {messages:?}"
        );
        assert!(
            messages.iter().any(|message| {
                message.contains("protocols[0].session.steps[1].decider_role")
                    && message.contains("approver")
                    && message.contains("is not declared by the protocol contract")
            }),
            "expected undeclared decider-role validation error, got {messages:?}"
        );
        assert!(
            messages.iter().any(|message| {
                message.contains("protocols[0].session.steps[1].branches[0].steps[0].role")
                    && message.contains("auditor")
                    && message.contains("is not declared by the protocol contract")
            }),
            "expected undeclared branch-role validation error, got {messages:?}"
        );
    }

    fn error_messages(errors: &[FabricIrValidationError]) -> Vec<String> {
        errors
            .iter()
            .map(|error| format!("{} => {}", error.field, error.message))
            .collect()
    }

    #[test]
    fn subject_family_defaults_and_mobility_lists_remain_stable() {
        assert_eq!(SubjectFamily::default(), SubjectFamily::Event);
        assert_eq!(
            SubjectFamily::ALL,
            [
                SubjectFamily::Command,
                SubjectFamily::Event,
                SubjectFamily::Reply,
                SubjectFamily::Control,
                SubjectFamily::ProtocolStep,
                SubjectFamily::CaptureSelector,
                SubjectFamily::DerivedView,
            ]
        );
        assert_eq!(
            MobilityPermission::ALL,
            [
                MobilityPermission::LocalOnly,
                MobilityPermission::Federated,
                MobilityPermission::StewardshipTransfer,
            ]
        );
        assert_eq!(
            MetadataDisclosure::ALL,
            [
                MetadataDisclosure::Full,
                MetadataDisclosure::Hashed,
                MetadataDisclosure::Redacted,
            ]
        );
    }

    #[test]
    fn reply_space_rules_reject_empty_prefixes() {
        for rule in [
            ReplySpaceRule::SharedPrefix {
                prefix: "   ".to_owned(),
            },
            ReplySpaceRule::DedicatedPrefix {
                prefix: String::new(),
            },
        ] {
            let mut errors = Vec::new();
            rule.validate_at("reply_space", &mut errors);
            let messages = error_messages(&errors);
            assert!(
                messages
                    .iter()
                    .any(|message| message.contains("reply-space prefix must not be empty")),
                "expected empty-prefix validation error, got {messages:?}"
            );
        }

        let mut errors = Vec::new();
        ReplySpaceRule::CallerInbox.validate_at("reply_space", &mut errors);
        assert!(errors.is_empty(), "caller inbox should always validate");
    }

    #[test]
    fn subject_schema_family_specific_rules_validate() {
        let default_subject = SubjectSchema::default();
        let mut errors = Vec::new();
        default_subject.validate_at("subject", &mut errors);
        assert!(errors.is_empty(), "default subject schema should validate");

        let command_subject = SubjectSchema {
            pattern: SubjectPattern::new("tenant.orders.command"),
            family: SubjectFamily::Command,
            delivery_class: DeliveryClass::ObligationBacked,
            evidence_policy: EvidencePolicy::default(),
            privacy_policy: PrivacyPolicy::default(),
            reply_space: Some(ReplySpaceRule::CallerInbox),
            mobility: MobilityPermission::Federated,
            quantitative_obligation: None,
        };
        let mut errors = Vec::new();
        command_subject.validate_at("command", &mut errors);
        assert!(errors.is_empty(), "command subject should validate");

        let reply_subject = SubjectSchema {
            family: SubjectFamily::Reply,
            reply_space: Some(ReplySpaceRule::CallerInbox),
            ..SubjectSchema::default()
        };
        let mut errors = Vec::new();
        reply_subject.validate_at("reply", &mut errors);
        let messages = error_messages(&errors);
        assert!(
            messages.iter().any(|message| message.contains(
                "event, reply, and derived-view subjects must not declare reply-space rules"
            )),
            "expected reply-space rejection for reply subject, got {messages:?}"
        );

        let control_subject = SubjectSchema {
            pattern: SubjectPattern::new("$SYS.health.ok"),
            family: SubjectFamily::Control,
            ..SubjectSchema::default()
        };
        let mut errors = Vec::new();
        control_subject.validate_at("control", &mut errors);
        assert!(
            errors.is_empty(),
            "control subject under $SYS should validate"
        );

        let capture_selector = SubjectSchema {
            pattern: SubjectPattern::new("tenant.capture.>"),
            family: SubjectFamily::CaptureSelector,
            ..SubjectSchema::default()
        };
        let mut errors = Vec::new();
        capture_selector.validate_at("capture", &mut errors);
        assert!(
            errors.is_empty(),
            "capture selector with wildcard should validate"
        );
    }

    #[test]
    fn cost_vector_baselines_increase_with_stronger_delivery_classes() {
        let ephemeral =
            CostVector::baseline_for_delivery_class(DeliveryClass::EphemeralInteractive);
        let durable = CostVector::baseline_for_delivery_class(DeliveryClass::DurableOrdered);
        let obligation = CostVector::baseline_for_delivery_class(DeliveryClass::ObligationBacked);
        let forensic = CostVector::baseline_for_delivery_class(DeliveryClass::ForensicReplayable);

        assert!(ephemeral.cheaper_or_equal(&durable));
        assert!(durable.cheaper_or_equal(&obligation));
        assert!(obligation.cheaper_or_equal(&forensic));
        assert!(forensic.more_expensive_on_any_dimension(&durable));
        assert!(durable.storage_amplification >= 1.0);
        assert!(forensic.evidence_bytes.typical_bytes > obligation.evidence_bytes.typical_bytes);
    }

    #[test]
    fn subject_cost_estimation_accounts_for_evidence_and_mobility() {
        let subject = SubjectSchema {
            pattern: SubjectPattern::new("tenant.orders.command"),
            family: SubjectFamily::Command,
            delivery_class: DeliveryClass::ObligationBacked,
            evidence_policy: EvidencePolicy {
                sampling_ratio: 1.0,
                retention: RetentionPolicy::Forever,
                record_payload_hashes: true,
                record_control_transitions: true,
                record_counterfactual_branches: true,
            },
            privacy_policy: PrivacyPolicy::default(),
            reply_space: Some(ReplySpaceRule::CallerInbox),
            mobility: MobilityPermission::StewardshipTransfer,
            quantitative_obligation: Some(QuantitativeObligationContract {
                target_latency: Duration::from_millis(25),
                ..QuantitativeObligationContract::default()
            }),
        };

        let baseline = CostVector::baseline_for_delivery_class(subject.delivery_class);
        let estimated = CostVector::estimate_subject(&subject);
        assert!(baseline.cheaper_or_equal(&estimated));
        assert!(estimated.storage_amplification > baseline.storage_amplification);
        assert!(estimated.control_plane_amplification > baseline.control_plane_amplification);
        assert!(estimated.evidence_bytes.typical_bytes > baseline.evidence_bytes.typical_bytes);
        assert!(estimated.restore_handoff_time.typical > baseline.restore_handoff_time.typical);
        assert!(estimated.tail_latency.p99 >= Duration::from_millis(25));
    }

    #[test]
    fn cost_vector_round_trips_through_json() {
        let original = CostVector::baseline_for_delivery_class(DeliveryClass::ForensicReplayable);

        let json =
            serde_json::to_string(&original).expect("cost vector should serialize for diagnostics");
        let decoded: CostVector =
            serde_json::from_str(&json).expect("cost vector should deserialize from diagnostics");

        assert_eq!(decoded, original);
    }

    #[test]
    fn service_contract_and_protocol_defaults_are_constructible() {
        let service = ServiceContract::default();
        let mut errors = Vec::new();
        service.validate_at("service", &mut errors);
        assert!(
            errors.is_empty(),
            "default service contract should validate"
        );

        let protocol = ProtocolContract::default();
        let mut errors = Vec::new();
        protocol.validate_at("protocol", &mut errors);
        assert!(
            errors.is_empty(),
            "default protocol contract should validate"
        );

        let invalid_operation = ServiceOperation {
            reply_space: None,
            delivery_class: DeliveryClass::ObligationBacked,
            ..ServiceOperation::default()
        };
        let mut errors = Vec::new();
        invalid_operation.validate_at("operation", &mut errors);
        let messages = error_messages(&errors);
        assert!(
            messages.iter().any(|message| message.contains(
                "obligation-backed and stronger service operations must declare a reply-space rule"
            )),
            "expected missing reply-space error, got {messages:?}"
        );
    }

    #[test]
    fn session_schema_validates_send_receive_choice_branch_and_end_shapes() {
        let session = SessionSchema {
            name: "checkout".to_owned(),
            steps: vec![
                SessionStep::Send {
                    role: "client".to_owned(),
                    subject: SubjectPattern::new("protocol.checkout.begin"),
                },
                SessionStep::Receive {
                    role: "inventory".to_owned(),
                    subject: SubjectPattern::new("protocol.checkout.reserve"),
                },
                SessionStep::Choice {
                    decider_role: "inventory".to_owned(),
                    branches: vec![
                        SessionBranch {
                            label: "reserved".to_owned(),
                            steps: vec![SessionStep::End],
                        },
                        SessionBranch {
                            label: "rejected".to_owned(),
                            steps: vec![SessionStep::End],
                        },
                    ],
                },
                SessionStep::End,
            ],
        };

        let mut errors = Vec::new();
        session.validate_at("session", &mut errors);
        assert!(errors.is_empty(), "session shape should validate");

        let invalid_choice = SessionSchema {
            name: "invalid-choice".to_owned(),
            steps: vec![
                SessionStep::Choice {
                    decider_role: String::new(),
                    branches: vec![SessionBranch {
                        label: String::new(),
                        steps: Vec::new(),
                    }],
                },
                SessionStep::End,
            ],
        };
        let mut errors = Vec::new();
        invalid_choice.validate_at("session", &mut errors);
        let messages = error_messages(&errors);
        assert!(
            messages
                .iter()
                .any(|message| message.contains("session choice decider role must not be empty")),
            "expected empty decider-role error, got {messages:?}"
        );
        assert!(
            messages
                .iter()
                .any(|message| message
                    .contains("session branch labels must be unique and non-empty")),
            "expected branch-label validation error, got {messages:?}"
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("session branch must contain at least one step")),
            "expected empty-branch validation error, got {messages:?}"
        );
    }

    #[test]
    fn consumer_policy_validation_enforces_ack_and_replay_mode_constraints() {
        let replayable = ConsumerPolicy {
            mode: ConsumerMode::Replayable,
            delivery_class: DeliveryClass::ObligationBacked,
            ack_kind: AckKind::Served,
            replay_window: Some(Duration::from_secs(30)),
            ..ConsumerPolicy::default()
        };
        let mut errors = Vec::new();
        replayable.validate_at("consumer", &mut errors);
        assert!(errors.is_empty(), "replayable consumer should validate");

        let missing_window = ConsumerPolicy {
            replay_window: None,
            ..replayable.clone()
        };
        let mut errors = Vec::new();
        missing_window.validate_at("consumer", &mut errors);
        let messages = error_messages(&errors);
        assert!(
            messages.iter().any(
                |message| message.contains("replayable consumers must declare a replay window")
            ),
            "expected missing replay-window error, got {messages:?}"
        );

        let window_on_durable = ConsumerPolicy {
            mode: ConsumerMode::Durable,
            replay_window: Some(Duration::from_secs(5)),
            ..ConsumerPolicy::default()
        };
        let mut errors = Vec::new();
        window_on_durable.validate_at("consumer", &mut errors);
        let messages = error_messages(&errors);
        assert!(
            messages.iter().any(|message| message
                .contains("consumer replay window is only valid for replayable consumers")),
            "expected replay-window mode error, got {messages:?}"
        );

        let weak_ack = ConsumerPolicy {
            delivery_class: DeliveryClass::DurableOrdered,
            ack_kind: AckKind::Accepted,
            ..ConsumerPolicy::default()
        };
        let mut errors = Vec::new();
        weak_ack.validate_at("consumer", &mut errors);
        let messages = error_messages(&errors);
        assert!(
            messages
                .iter()
                .any(|message| message.contains("is weaker than the minimum")),
            "expected weak-ack validation error, got {messages:?}"
        );
    }

    #[test]
    fn schema_policies_and_quantitative_contracts_validate_boundary_values() {
        let capability = CapabilityTokenSchema {
            name: String::new(),
            families: Vec::new(),
            delivery_classes: Vec::new(),
            permissions: Vec::new(),
        };
        let mut errors = Vec::new();
        capability.validate_at("capability", &mut errors);
        let capability_messages = error_messages(&errors);
        assert!(
            capability_messages
                .iter()
                .any(|message| message.contains("capability token schema name must not be empty"))
        );
        assert!(capability_messages.iter().any(|message| {
            message.contains("capability token schema must authorize at least one subject family")
        }));
        assert!(capability_messages.iter().any(|message| {
            message.contains("capability token schema must authorize at least one delivery class")
        }));
        assert!(capability_messages.iter().any(|message| {
            message.contains("capability token schema must authorize at least one permission")
        }));

        let evidence = EvidencePolicy {
            sampling_ratio: 1.5,
            ..EvidencePolicy::default()
        };
        let privacy = PrivacyPolicy {
            name: String::new(),
            noise_budget: Some(0.0),
            ..PrivacyPolicy::default()
        };
        let cut = CutPolicy {
            name: String::new(),
            trigger: CutTrigger::AtEvidenceBudgetBytes { bytes: 0 },
            retention: RetentionPolicy::RetainForEvents { events: 0 },
            materialization: MaterializationPolicy::MetadataOnly,
        };
        let branch = BranchPolicy {
            name: String::new(),
            retention: RetentionPolicy::RetainFor {
                duration: Duration::ZERO,
            },
            ..BranchPolicy::default()
        };
        let contract = QuantitativeObligationContract {
            name: String::new(),
            target_latency: Duration::ZERO,
            target_probability: 0.0,
            retry_law: RetryLaw::Fixed {
                max_retries: 0,
                delay: Duration::ZERO,
            },
            degradation_policy: DegradationPolicy::DowngradeTo {
                class: DeliveryClass::ForensicReplayable,
            },
            ..QuantitativeObligationContract::default()
        };

        let mut errors = Vec::new();
        evidence.validate_at("evidence", &mut errors);
        privacy.validate_at("privacy", &mut errors);
        cut.validate_at("cut", &mut errors);
        branch.validate_at("branch", &mut errors);
        contract.validate_at("contract", &mut errors);
        let messages = error_messages(&errors);

        assert!(
            messages.iter().any(|message| {
                message.contains("evidence sampling ratio must be a finite value in [0.0, 1.0]")
            }),
            "expected sampling-ratio validation error, got {messages:?}"
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("privacy policy name must not be empty")),
            "expected privacy-name validation error, got {messages:?}"
        );
        assert!(
            messages.iter().any(|message| message
                .contains("privacy noise budget must be a finite value greater than zero")),
            "expected privacy-budget validation error, got {messages:?}"
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("cut policy name must not be empty")),
            "expected cut-name validation error, got {messages:?}"
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("cut evidence budget must be greater than zero")),
            "expected cut-trigger validation error, got {messages:?}"
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("retention event count must be greater than zero")),
            "expected retention validation error, got {messages:?}"
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("branch policy name must not be empty")),
            "expected branch-name validation error, got {messages:?}"
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("retention duration must be greater than zero")),
            "expected branch-retention validation error, got {messages:?}"
        );
        assert!(
            messages.iter().any(|message| {
                message.contains("quantitative obligation contract name must not be empty")
            }),
            "expected quantitative-contract name error, got {messages:?}"
        );
        assert!(
            messages
                .iter()
                .any(|message| message
                    .contains("quantitative target latency must be greater than zero")),
            "expected quantitative latency error, got {messages:?}"
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("quantitative target probability must be")),
            "expected quantitative probability error, got {messages:?}"
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("fixed retry law must allow at least one retry")),
            "expected fixed-retry count error, got {messages:?}"
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("fixed retry delay must be greater than zero")),
            "expected fixed-retry delay error, got {messages:?}"
        );
        assert!(
            messages.iter().any(|message| {
                message.contains(
                    "degradation downgrade target must be strictly weaker than the baseline delivery class",
                )
            }),
            "expected downgrade-target validation error, got {messages:?}"
        );
    }
