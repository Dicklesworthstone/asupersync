    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::messaging::class::AckKind;
    use crate::messaging::ir::{
        BranchPolicy, CapabilityTokenSchema, ConsumerPolicy, MorphismPlan, ProtocolContract,
        ReplySpaceRule, RetryLaw, ServiceOperation, SessionSchema,
    };

    fn retained_event_policy() -> EvidencePolicy {
        EvidencePolicy {
            retention: RetentionPolicy::RetainFor {
                duration: Duration::from_secs(60),
            },
            ..EvidencePolicy::default()
        }
    }

    fn valid_ir() -> FabricIr {
        FabricIr {
            subjects: vec![
                SubjectSchema {
                    pattern: SubjectPattern::new("tenant.orders.command"),
                    family: SubjectFamily::Command,
                    delivery_class: DeliveryClass::ObligationBacked,
                    evidence_policy: EvidencePolicy::default(),
                    privacy_policy: PrivacyPolicy::default(),
                    reply_space: Some(ReplySpaceRule::CallerInbox),
                    mobility: MobilityPermission::LocalOnly,
                    quantitative_obligation: None,
                },
                SubjectSchema {
                    pattern: SubjectPattern::new("tenant.orders.event"),
                    family: SubjectFamily::Event,
                    delivery_class: DeliveryClass::DurableOrdered,
                    evidence_policy: retained_event_policy(),
                    privacy_policy: PrivacyPolicy::default(),
                    reply_space: None,
                    mobility: MobilityPermission::Federated,
                    quantitative_obligation: None,
                },
                SubjectSchema {
                    pattern: SubjectPattern::new("tenant.orders.protocol.step"),
                    family: SubjectFamily::ProtocolStep,
                    delivery_class: DeliveryClass::DurableOrdered,
                    evidence_policy: retained_event_policy(),
                    privacy_policy: PrivacyPolicy::default(),
                    reply_space: None,
                    mobility: MobilityPermission::LocalOnly,
                    quantitative_obligation: None,
                },
                SubjectSchema {
                    pattern: SubjectPattern::new("tenant.orders.reply"),
                    family: SubjectFamily::Reply,
                    delivery_class: DeliveryClass::DurableOrdered,
                    evidence_policy: retained_event_policy(),
                    privacy_policy: PrivacyPolicy::default(),
                    reply_space: None,
                    mobility: MobilityPermission::LocalOnly,
                    quantitative_obligation: None,
                },
            ],
            morphisms: vec![MorphismPlan {
                name: "edge-export".to_owned(),
                source_pattern: SubjectPattern::new("tenant.orders.event"),
                target_prefix: "edge.orders".to_owned(),
                allowed_families: vec![SubjectFamily::Event],
                transforms: vec![MorphismTransform::RenamePrefix {
                    from: "tenant.orders".to_owned(),
                    to: "edge.orders".to_owned(),
                }],
            }],
            services: vec![ServiceContract {
                name: "orders.service".to_owned(),
                operations: vec![ServiceOperation {
                    name: "create".to_owned(),
                    request: SubjectPattern::new("tenant.orders.command"),
                    reply_space: Some(ReplySpaceRule::CallerInbox),
                    delivery_class: DeliveryClass::ObligationBacked,
                    idempotent: true,
                }],
                default_consumer_policy: ConsumerPolicy::default(),
                required_capability: Some("orders.request".to_owned()),
                quantitative_obligation: Some(QuantitativeObligationContract {
                    name: "orders.slo".to_owned(),
                    class: DeliveryClass::ObligationBacked,
                    target_latency: Duration::from_millis(25),
                    target_probability: 0.99,
                    retry_law: RetryLaw::default(),
                    degradation_policy: super::super::ir::DegradationPolicy::default(),
                }),
            }],
            protocols: vec![ProtocolContract {
                name: "orders.protocol".to_owned(),
                roles: vec!["caller".to_owned(), "service".to_owned()],
                entry_subject: SubjectPattern::new("tenant.orders.protocol.step"),
                session: SessionSchema {
                    name: "orders.session".to_owned(),
                    steps: vec![
                        SessionStep::Send {
                            role: "caller".to_owned(),
                            subject: SubjectPattern::new("tenant.orders.protocol.step"),
                        },
                        SessionStep::Receive {
                            role: "service".to_owned(),
                            subject: SubjectPattern::new("tenant.orders.reply"),
                        },
                        SessionStep::End,
                    ],
                },
                branch_policy: BranchPolicy::default(),
            }],
            consumers: vec![ConsumerPolicy {
                name: "orders.replay".to_owned(),
                mode: ConsumerMode::Replayable,
                delivery_class: DeliveryClass::DurableOrdered,
                ack_kind: AckKind::Recoverable,
                max_pending: 256,
                max_deliver: 2,
                replay_window: Some(Duration::from_secs(30)),
            }],
            capability_tokens: vec![CapabilityTokenSchema {
                name: "orders.request".to_owned(),
                families: vec![SubjectFamily::Command],
                delivery_classes: vec![DeliveryClass::ObligationBacked],
                permissions: vec![CapabilityPermission::Request],
            }],
            ..FabricIr::default()
        }
    }

    #[test]
    fn compiler_rejects_invalid_ir_before_estimating_costs() {
        let ir = FabricIr {
            schema_version: 999,
            ..FabricIr::default()
        };

        let err = FabricCompiler::compile(&ir).expect_err("invalid schema version should fail");
        match err {
            FabricCompilerError::Validation { errors_len, errors } => {
                assert_eq!(errors_len, errors.len());
                assert!(!errors.is_empty());
            }
        }
    }

    #[test]
    fn compiler_emits_artifacts_warnings_and_aggregate_envelope() {
        let report = FabricCompiler::compile(&valid_ir()).expect("valid fabric ir should compile");
        assert_eq!(report.subject_costs.len(), 4);
        assert!(report.warnings.is_empty());
        assert!(report.errors.is_empty());
        assert_eq!(
            report
                .subject_costs
                .iter()
                .map(|subject| subject.pattern.as_str())
                .collect::<Vec<_>>(),
            vec![
                "tenant.orders.command",
                "tenant.orders.event",
                "tenant.orders.protocol.step",
                "tenant.orders.reply",
            ]
        );
        assert!(
            report
                .artifacts
                .iter()
                .any(|artifact| artifact.kind == CompiledArtifactKind::Morphism
                    && artifact.name == "edge-export")
        );
        assert!(
            report
                .artifacts
                .iter()
                .any(|artifact| artifact.kind == CompiledArtifactKind::Service
                    && artifact.name == "orders.service")
        );
        assert!(
            report
                .aggregate_cost
                .more_expensive_on_any_dimension(&CostVector::zero())
        );
    }

    #[test]
    fn compiler_rejects_required_capability_without_request_permission() {
        let mut ir = valid_ir();
        ir.capability_tokens[0].permissions = vec![CapabilityPermission::Publish];

        let err = FabricCompiler::compile(&ir).expect_err("invalid capability should fail");
        let FabricCompilerError::Validation { errors, .. } = err;
        assert!(
            errors
                .iter()
                .any(|error| error.field == "services[0].required_capability"
                    && error.message.contains("request permission")),
            "expected request-permission error, got {errors:?}"
        );
    }

    #[test]
    fn compiler_rejects_irreversible_morphism_for_reply_space_subjects() {
        let mut ir = valid_ir();
        ir.morphisms[0] = MorphismPlan {
            name: "command-rewrite".to_owned(),
            source_pattern: SubjectPattern::new("tenant.orders.command"),
            target_prefix: "edge.orders".to_owned(),
            allowed_families: vec![SubjectFamily::Command],
            transforms: vec![MorphismTransform::FilterFamily {
                family: SubjectFamily::Command,
            }],
        };

        let err = FabricCompiler::compile(&ir).expect_err("irreversible morphism should fail");
        let FabricCompilerError::Validation { errors, .. } = err;
        assert!(
            errors
                .iter()
                .any(|error| error.field == "morphisms[0].transforms"
                    && error.message.contains("structurally reversible")),
            "expected reversibility error, got {errors:?}"
        );
    }

    #[test]
    fn compiler_rejects_forensic_subject_without_retained_evidence() {
        let mut ir = valid_ir();
        ir.subjects[0].delivery_class = DeliveryClass::ForensicReplayable;

        let err = FabricCompiler::compile(&ir).expect_err("forensic subject should fail");
        let FabricCompilerError::Validation { errors, .. } = err;
        assert!(
            errors.iter().any(
                |error| error.field == "subjects[0].evidence_policy.retention"
                    && error.message.contains("retain evidence")
            ),
            "expected replay-retention error, got {errors:?}"
        );
    }

    #[test]
    fn compiler_warns_when_redaction_omits_literal_scrubbing() {
        let mut ir = valid_ir();
        ir.subjects[1].privacy_policy = PrivacyPolicy {
            name: "redacted".to_owned(),
            metadata_disclosure: MetadataDisclosure::Redacted,
            redact_subject_literals: false,
            noise_budget: None,
            allow_cross_tenant_flow: false,
        };

        let report = FabricCompiler::compile(&ir).expect("warning-only IR should compile");
        assert!(
            report.warnings.iter().any(
                |warning| warning.field == "subjects[1].privacy_policy.redact_subject_literals"
            ),
            "expected redaction warning, got {:?}",
            report.warnings
        );
    }
