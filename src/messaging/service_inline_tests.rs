    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::messaging::ir::ReplySpaceRule;
    use crate::messaging::morphism::{
        FabricCapability, MorphismClass, MorphismPlanDirection, ResponsePolicy,
        ReversibilityRequirement, SharingPolicy, SubjectTransform,
    };
    use crate::messaging::subject::SubjectPattern;
    use crate::record::{ObligationAbortReason, ObligationState};
    use crate::util::ArenaIndex;

    fn provider_terms() -> ProviderTerms {
        ProviderTerms {
            admissible_classes: DeliveryClassPolicy::new(
                DeliveryClass::ObligationBacked,
                [DeliveryClass::ObligationBacked, DeliveryClass::MobilitySafe],
            )
            .expect("provider policy"),
            guaranteed_durability: DeliveryClass::MobilitySafe,
            compensation_policy: CompensationSemantics::BestEffort,
            mobility_constraint: MobilityConstraint::Pinned,
            evidence_level: EvidenceLevel::Detailed,
        }
    }

    fn provider_terms_with_mobility(mobility_constraint: MobilityConstraint) -> ProviderTerms {
        ProviderTerms {
            mobility_constraint,
            ..provider_terms()
        }
    }

    fn contract() -> ServiceContractSchema {
        ServiceContractSchema {
            budget_semantics: BudgetSemantics {
                honor_priority_hints: true,
                ..BudgetSemantics::default()
            },
            compensation_semantics: CompensationSemantics::BestEffort,
            mobility_constraints: MobilityConstraint::Unrestricted,
            evidence_requirements: EvidenceLevel::Standard,
            ..ServiceContractSchema::default()
        }
    }

    fn namespace() -> NamespaceKernel {
        NamespaceKernel::new("acme", "orders").expect("namespace kernel")
    }

    fn service_subject() -> Subject {
        Subject::new("tenant.acme.service.orders.lookup")
    }

    fn service_boundary() -> FabricServiceBoundary {
        let registration =
            ServiceRegistration::new("fabric.echo", contract(), provider_terms()).expect("valid");
        FabricServiceBoundary::new(namespace(), service_subject(), registration)
            .expect("valid service boundary")
    }

    fn transferable_service_boundary() -> FabricServiceBoundary {
        let registration = ServiceRegistration::new(
            "fabric.echo",
            contract(),
            provider_terms_with_mobility(MobilityConstraint::Unrestricted),
        )
        .expect("valid");
        FabricServiceBoundary::new(namespace(), service_subject(), registration)
            .expect("valid service boundary")
    }

    fn service_boundary_with_name(service_name: &str) -> FabricServiceBoundary {
        let registration = ServiceRegistration::new(
            service_name,
            contract(),
            provider_terms_with_mobility(MobilityConstraint::Unrestricted),
        )
        .expect("valid");
        FabricServiceBoundary::new(namespace(), service_subject(), registration)
            .expect("valid service boundary")
    }

    fn inventory_service_boundary() -> FabricServiceBoundary {
        let registration = ServiceRegistration::new(
            "fabric.inventory",
            contract(),
            provider_terms_with_mobility(MobilityConstraint::Unrestricted),
        )
        .expect("valid");
        FabricServiceBoundary::new(
            NamespaceKernel::new("acme", "inventory").expect("namespace kernel"),
            Subject::new("tenant.acme.service.inventory.lookup"),
            registration,
        )
        .expect("valid service boundary")
    }

    fn authoritative_import_morphism() -> Morphism {
        Morphism {
            source_language: SubjectPattern::new("tenant.acme.service.orders.lookup"),
            dest_language: SubjectPattern::new("tenant.acme.service.edge-orders.lookup"),
            class: MorphismClass::Authoritative,
            transform: SubjectTransform::RenamePrefix {
                from: SubjectPattern::new("tenant.acme.service.orders.lookup"),
                to: SubjectPattern::new("tenant.acme.service.edge-orders.lookup"),
            },
            reversibility: ReversibilityRequirement::Bijective,
            capability_requirements: vec![
                FabricCapability::CarryAuthority,
                FabricCapability::ReplyAuthority,
            ],
            sharing_policy: SharingPolicy::TenantScoped,
            response_policy: ResponsePolicy::ReplyAuthoritative,
            ..Morphism::default()
        }
    }

    fn make_task() -> TaskId {
        TaskId::from_arena(ArenaIndex::new(11, 0))
    }

    fn make_region() -> RegionId {
        RegionId::from_arena(ArenaIndex::new(7, 0))
    }

    fn workflow_step(
        step_id: &str,
        subject: &str,
        obligations: Vec<WorkflowObligationRole>,
        compensation_path: &[&str],
    ) -> WorkflowStep {
        WorkflowStep::new(
            step_id,
            Subject::new(subject),
            obligations,
            compensation_path
                .iter()
                .map(|subject| Subject::new(*subject))
                .collect(),
            Some(Duration::from_secs(5)),
        )
        .expect("valid workflow step")
    }

    #[test]
    fn service_registration_accepts_valid_contract() {
        let registration =
            ServiceRegistration::new("fabric.echo", contract(), provider_terms()).expect("valid");

        assert_eq!(registration.service_name, "fabric.echo");
        assert_eq!(
            registration.provider_terms.guaranteed_durability,
            DeliveryClass::MobilitySafe
        );
    }

    #[test]
    fn service_boundary_binds_request_and_control_subjects() {
        let boundary = service_boundary();
        let subjects = boundary.control_subjects().expect("subjects");

        assert_eq!(
            boundary.request_subject().as_str(),
            "tenant.acme.service.orders.lookup"
        );
        assert_eq!(
            subjects.discovery.as_str(),
            "tenant.acme.service.orders.discover"
        );
        assert_eq!(
            subjects.health.as_str(),
            "$SYS.FABRIC.HEALTH.TENANT.acme.SERVICE.orders.status"
        );
        assert_eq!(
            subjects.advisories.as_str(),
            "$SYS.FABRIC.ROUTE.TENANT.acme.SERVICE.orders.advisory"
        );
    }

    #[test]
    fn service_boundary_registers_namespace_control_handlers() {
        let boundary = service_boundary();
        let subjects = boundary.control_subjects().expect("subjects");
        let mut registry = ControlRegistry::new();

        let handlers = boundary
            .register_control_handlers(&mut registry)
            .expect("register handlers");

        let health_matches = registry.matching_handlers(&subjects.health);
        assert_eq!(health_matches.len(), 1);
        assert_eq!(health_matches[0].id, handlers.health);

        let advisory_matches = registry.matching_handlers(&subjects.advisories);
        assert_eq!(advisory_matches.len(), 1);
        assert_eq!(advisory_matches[0].id, handlers.advisories);
    }

    #[test]
    fn service_boundary_admission_issues_request_certificate() {
        let boundary = service_boundary();
        let caller = CallerOptions {
            requested_class: Some(DeliveryClass::MobilitySafe),
            timeout_override: Some(Duration::from_secs(5)),
            priority_hint: Some(200),
        };

        let admission = boundary
            .admit_request(
                "req-service-boundary",
                "caller-a",
                &caller,
                ReplySpaceRule::CallerInbox,
                0xfeed_u64,
                Time::from_nanos(10),
            )
            .expect("admit request");

        assert_eq!(
            admission.validated.delivery_class,
            DeliveryClass::MobilitySafe
        );
        assert_eq!(
            admission.certificate.subject,
            "tenant.acme.service.orders.lookup"
        );
        assert_eq!(admission.certificate.service_class, "fabric.echo");
        assert_eq!(
            admission.certificate.reply_space_rule,
            ReplySpaceRule::CallerInbox
        );
    }

    #[test]
    fn service_boundary_transfer_compiles_import_plan_and_updates_obligation() {
        let boundary = transferable_service_boundary();
        let mut ledger = ObligationLedger::new();
        let caller = CallerOptions {
            requested_class: Some(DeliveryClass::MobilitySafe),
            ..CallerOptions::default()
        };
        let admission = boundary
            .admit_request(
                "req-transfer",
                "caller-a",
                &caller,
                ReplySpaceRule::CallerInbox,
                99,
                Time::from_nanos(1),
            )
            .expect("admission");
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-transfer",
            "caller-a",
            "orders-origin",
            boundary.request_subject().as_str(),
            admission.validated.delivery_class,
            make_task(),
            make_region(),
            Time::from_nanos(2),
            admission.validated.timeout,
        )
        .expect("allocate obligation");

        let plan = boundary
            .transfer_request_via_import(
                &admission,
                &mut obligation,
                ImportTransferRequest::new(
                    "orders-edge",
                    Subject::new("tenant.acme.service.edge-orders.lookup"),
                    "import/orders->edge",
                    Some(ReplySpaceRule::DedicatedPrefix {
                        prefix: "tenant.acme.service.edge-orders.lookup".to_owned(),
                    }),
                    Time::from_nanos(3),
                ),
                &authoritative_import_morphism(),
            )
            .expect("transfer through import plan");

        assert_eq!(obligation.subject, "tenant.acme.service.edge-orders.lookup");
        assert_eq!(obligation.callee, "orders-edge");
        assert_eq!(obligation.lineage.len(), 1);
        assert_eq!(obligation.lineage[0].morphism, "import/orders->edge");
        assert_eq!(plan.direction, MorphismPlanDirection::Import);
        assert_eq!(
            plan.selected_reply_space,
            Some(ReplySpaceRule::DedicatedPrefix {
                prefix: "tenant.acme.service.edge-orders.lookup".to_owned(),
            })
        );
    }

    #[test]
    fn service_boundary_rejects_import_morphism_outside_request_subject() {
        let boundary = service_boundary();
        let morphism = Morphism {
            source_language: SubjectPattern::new("tenant.acme.service.inventory.lookup"),
            ..authoritative_import_morphism()
        };

        let error = boundary
            .compile_import_plan(&morphism, None)
            .expect_err("morphism should not cover this boundary");

        assert_eq!(
            error,
            ServiceBoundaryError::MorphismDoesNotCoverBoundary {
                subject: "tenant.acme.service.orders.lookup".to_owned(),
                source_language: "tenant.acme.service.inventory.lookup".to_owned(),
            }
        );
    }

    #[test]
    fn service_boundary_transfer_rejects_non_unrestricted_mobility() {
        let boundary = service_boundary();
        let mut ledger = ObligationLedger::new();
        let caller = CallerOptions {
            requested_class: Some(DeliveryClass::MobilitySafe),
            ..CallerOptions::default()
        };
        let admission = boundary
            .admit_request(
                "req-transfer-pinned",
                "caller-a",
                &caller,
                ReplySpaceRule::CallerInbox,
                11,
                Time::from_nanos(1),
            )
            .expect("admission");
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-transfer-pinned",
            "caller-a",
            "orders-origin",
            boundary.request_subject().as_str(),
            admission.validated.delivery_class,
            make_task(),
            make_region(),
            Time::from_nanos(2),
            admission.validated.timeout,
        )
        .expect("allocate obligation");

        let error = boundary
            .transfer_request_via_import(
                &admission,
                &mut obligation,
                ImportTransferRequest::new(
                    "orders-edge",
                    Subject::new("tenant.acme.service.edge-orders.lookup"),
                    "import/orders->edge",
                    None,
                    Time::from_nanos(3),
                ),
                &authoritative_import_morphism(),
            )
            .expect_err("pinned mobility should fail closed");

        assert_eq!(
            error,
            ServiceBoundaryError::TransferRequiresUnrestrictedMobility {
                constraint: MobilityConstraint::Pinned,
                target_subject: "tenant.acme.service.edge-orders.lookup".to_owned(),
            }
        );
        assert!(obligation.lineage.is_empty());
        assert_eq!(obligation.subject, boundary.request_subject().as_str());
    }

    #[test]
    fn service_boundary_transfer_rejects_target_outside_destination_language() {
        let boundary = transferable_service_boundary();
        let mut ledger = ObligationLedger::new();
        let caller = CallerOptions {
            requested_class: Some(DeliveryClass::MobilitySafe),
            ..CallerOptions::default()
        };
        let admission = boundary
            .admit_request(
                "req-transfer-miss",
                "caller-a",
                &caller,
                ReplySpaceRule::CallerInbox,
                12,
                Time::from_nanos(1),
            )
            .expect("admission");
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-transfer-miss",
            "caller-a",
            "orders-origin",
            boundary.request_subject().as_str(),
            admission.validated.delivery_class,
            make_task(),
            make_region(),
            Time::from_nanos(2),
            admission.validated.timeout,
        )
        .expect("allocate obligation");

        let error = boundary
            .transfer_request_via_import(
                &admission,
                &mut obligation,
                ImportTransferRequest::new(
                    "orders-edge",
                    Subject::new("tenant.acme.service.wrong.lookup"),
                    "import/orders->edge",
                    None,
                    Time::from_nanos(3),
                ),
                &authoritative_import_morphism(),
            )
            .expect_err("target outside morphism destination should fail closed");

        assert_eq!(
            error,
            ServiceBoundaryError::TargetOutsideMorphismDestination {
                subject: "tenant.acme.service.wrong.lookup".to_owned(),
                dest_language: "tenant.acme.service.edge-orders.lookup".to_owned(),
            }
        );
        assert!(obligation.lineage.is_empty());
        assert_eq!(obligation.subject, boundary.request_subject().as_str());
    }

    #[test]
    fn service_boundary_transfer_rejects_broad_destination_language_for_subject_only_transfer() {
        let boundary = transferable_service_boundary();
        let mut ledger = ObligationLedger::new();
        let caller = CallerOptions {
            requested_class: Some(DeliveryClass::MobilitySafe),
            ..CallerOptions::default()
        };
        let admission = boundary
            .admit_request(
                "req-transfer-broad-dest",
                "caller-a",
                &caller,
                ReplySpaceRule::CallerInbox,
                22,
                Time::from_nanos(1),
            )
            .expect("admission");
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-transfer-broad-dest",
            "caller-a",
            "orders-origin",
            boundary.request_subject().as_str(),
            admission.validated.delivery_class,
            make_task(),
            make_region(),
            Time::from_nanos(2),
            admission.validated.timeout,
        )
        .expect("allocate obligation");
        let broad_destination = Morphism {
            dest_language: SubjectPattern::new("tenant.acme.service.edge-orders.>"),
            ..authoritative_import_morphism()
        };

        let error = boundary
            .transfer_request_via_import(
                &admission,
                &mut obligation,
                ImportTransferRequest::new(
                    "orders-edge",
                    Subject::new("tenant.acme.service.edge-orders.lookup"),
                    "import/orders->edge",
                    None,
                    Time::from_nanos(3),
                ),
                &broad_destination,
            )
            .expect_err("broad destination language should fail closed");

        assert_eq!(
            error,
            ServiceBoundaryError::TransferRequiresExactMorphismDestination {
                target_subject: "tenant.acme.service.edge-orders.lookup".to_owned(),
                dest_language: "tenant.acme.service.edge-orders.>".to_owned(),
            }
        );
        assert!(obligation.lineage.is_empty());
        assert_eq!(obligation.subject, boundary.request_subject().as_str());
    }

    #[test]
    fn service_boundary_transfer_rejects_admission_request_mismatch() {
        let boundary = transferable_service_boundary();
        let mut ledger = ObligationLedger::new();
        let caller = CallerOptions {
            requested_class: Some(DeliveryClass::MobilitySafe),
            ..CallerOptions::default()
        };
        let admission = boundary
            .admit_request(
                "req-transfer-a",
                "caller-a",
                &caller,
                ReplySpaceRule::CallerInbox,
                13,
                Time::from_nanos(1),
            )
            .expect("admission");
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-transfer-b",
            "caller-a",
            "orders-origin",
            boundary.request_subject().as_str(),
            admission.validated.delivery_class,
            make_task(),
            make_region(),
            Time::from_nanos(2),
            admission.validated.timeout,
        )
        .expect("allocate obligation");

        let error = boundary
            .transfer_request_via_import(
                &admission,
                &mut obligation,
                ImportTransferRequest::new(
                    "orders-edge",
                    Subject::new("tenant.acme.service.edge-orders.lookup"),
                    "import/orders->edge",
                    None,
                    Time::from_nanos(3),
                ),
                &authoritative_import_morphism(),
            )
            .expect_err("mismatched admission should fail closed");

        assert_eq!(
            error,
            ServiceBoundaryError::AdmissionRequestMismatch {
                admission_request_id: "req-transfer-a".to_owned(),
                obligation_request_id: "req-transfer-b".to_owned(),
            }
        );
        assert!(obligation.lineage.is_empty());
        assert_eq!(obligation.subject, boundary.request_subject().as_str());
    }

    #[test]
    fn service_boundary_transfer_rejects_obligation_outside_boundary_subject() {
        let boundary = transferable_service_boundary();
        let mut ledger = ObligationLedger::new();
        let caller = CallerOptions {
            requested_class: Some(DeliveryClass::MobilitySafe),
            ..CallerOptions::default()
        };
        let admission = boundary
            .admit_request(
                "req-transfer-shifted",
                "caller-a",
                &caller,
                ReplySpaceRule::CallerInbox,
                14,
                Time::from_nanos(1),
            )
            .expect("admission");
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-transfer-shifted",
            "caller-a",
            "orders-origin",
            boundary.request_subject().as_str(),
            admission.validated.delivery_class,
            make_task(),
            make_region(),
            Time::from_nanos(2),
            admission.validated.timeout,
        )
        .expect("allocate obligation");
        obligation.subject = "tenant.acme.service.edge-orders.lookup".to_owned();

        let error = boundary
            .transfer_request_via_import(
                &admission,
                &mut obligation,
                ImportTransferRequest::new(
                    "orders-edge",
                    Subject::new("tenant.acme.service.edge-orders.lookup"),
                    "import/orders->edge",
                    None,
                    Time::from_nanos(3),
                ),
                &authoritative_import_morphism(),
            )
            .expect_err("obligation outside boundary should fail closed");

        assert_eq!(
            error,
            ServiceBoundaryError::ObligationOutsideBoundary {
                subject: "tenant.acme.service.edge-orders.lookup".to_owned(),
                boundary_subject: "tenant.acme.service.orders.lookup".to_owned(),
            }
        );
        assert!(obligation.lineage.is_empty());
    }

    #[test]
    fn service_boundary_transfer_rejects_admission_subject_mismatch() {
        let boundary = transferable_service_boundary();
        let other_boundary = inventory_service_boundary();
        let mut ledger = ObligationLedger::new();
        let caller = CallerOptions {
            requested_class: Some(DeliveryClass::MobilitySafe),
            ..CallerOptions::default()
        };
        let admission = other_boundary
            .admit_request(
                "req-transfer-subject",
                "caller-a",
                &caller,
                ReplySpaceRule::CallerInbox,
                15,
                Time::from_nanos(1),
            )
            .expect("admission");
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-transfer-subject",
            "caller-a",
            "orders-origin",
            boundary.request_subject().as_str(),
            admission.certificate.delivery_class,
            make_task(),
            make_region(),
            Time::from_nanos(2),
            admission.certificate.timeout,
        )
        .expect("allocate obligation");

        let error = boundary
            .transfer_request_via_import(
                &admission,
                &mut obligation,
                ImportTransferRequest::new(
                    "orders-edge",
                    Subject::new("tenant.acme.service.edge-orders.lookup"),
                    "import/orders->edge",
                    None,
                    Time::from_nanos(3),
                ),
                &authoritative_import_morphism(),
            )
            .expect_err("admission from another boundary should fail closed");

        assert_eq!(
            error,
            ServiceBoundaryError::AdmissionSubjectMismatch {
                admission_subject: "tenant.acme.service.inventory.lookup".to_owned(),
                boundary_subject: "tenant.acme.service.orders.lookup".to_owned(),
            }
        );
        assert!(obligation.lineage.is_empty());
        assert_eq!(obligation.subject, boundary.request_subject().as_str());
    }

    #[test]
    fn service_boundary_transfer_rejects_admission_service_mismatch() {
        let boundary = transferable_service_boundary();
        let other_boundary = service_boundary_with_name("fabric.inventory");
        let mut ledger = ObligationLedger::new();
        let caller = CallerOptions {
            requested_class: Some(DeliveryClass::MobilitySafe),
            ..CallerOptions::default()
        };
        let admission = other_boundary
            .admit_request(
                "req-transfer-service",
                "caller-a",
                &caller,
                ReplySpaceRule::CallerInbox,
                16,
                Time::from_nanos(1),
            )
            .expect("admission");
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-transfer-service",
            "caller-a",
            "orders-origin",
            boundary.request_subject().as_str(),
            admission.certificate.delivery_class,
            make_task(),
            make_region(),
            Time::from_nanos(2),
            admission.certificate.timeout,
        )
        .expect("allocate obligation");

        let error = boundary
            .transfer_request_via_import(
                &admission,
                &mut obligation,
                ImportTransferRequest::new(
                    "orders-edge",
                    Subject::new("tenant.acme.service.edge-orders.lookup"),
                    "import/orders->edge",
                    None,
                    Time::from_nanos(3),
                ),
                &authoritative_import_morphism(),
            )
            .expect_err("admission from another service should fail closed");

        assert_eq!(
            error,
            ServiceBoundaryError::AdmissionServiceMismatch {
                admission_service: "fabric.inventory".to_owned(),
                boundary_service: "fabric.echo".to_owned(),
            }
        );
        assert!(obligation.lineage.is_empty());
        assert_eq!(obligation.subject, boundary.request_subject().as_str());
    }

    #[test]
    fn service_boundary_transfer_rejects_admission_caller_mismatch() {
        let boundary = transferable_service_boundary();
        let mut ledger = ObligationLedger::new();
        let caller = CallerOptions {
            requested_class: Some(DeliveryClass::MobilitySafe),
            ..CallerOptions::default()
        };
        let admission = boundary
            .admit_request(
                "req-transfer-caller",
                "caller-b",
                &caller,
                ReplySpaceRule::CallerInbox,
                17,
                Time::from_nanos(1),
            )
            .expect("admission");
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-transfer-caller",
            "caller-a",
            "orders-origin",
            boundary.request_subject().as_str(),
            admission.certificate.delivery_class,
            make_task(),
            make_region(),
            Time::from_nanos(2),
            admission.certificate.timeout,
        )
        .expect("allocate obligation");

        let error = boundary
            .transfer_request_via_import(
                &admission,
                &mut obligation,
                ImportTransferRequest::new(
                    "orders-edge",
                    Subject::new("tenant.acme.service.edge-orders.lookup"),
                    "import/orders->edge",
                    None,
                    Time::from_nanos(3),
                ),
                &authoritative_import_morphism(),
            )
            .expect_err("caller mismatch should fail closed");

        assert_eq!(
            error,
            ServiceBoundaryError::AdmissionCallerMismatch {
                admission_caller: "caller-b".to_owned(),
                obligation_caller: "caller-a".to_owned(),
            }
        );
        assert!(obligation.lineage.is_empty());
        assert_eq!(obligation.subject, boundary.request_subject().as_str());
    }

    #[test]
    fn service_boundary_transfer_rejects_admission_delivery_class_mismatch() {
        let boundary = transferable_service_boundary();
        let mut ledger = ObligationLedger::new();
        let default_admission = boundary
            .admit_request(
                "req-transfer-class",
                "caller-a",
                &CallerOptions::default(),
                ReplySpaceRule::CallerInbox,
                18,
                Time::from_nanos(1),
            )
            .expect("default admission");
        let admission = boundary
            .admit_request(
                "req-transfer-class",
                "caller-a",
                &CallerOptions {
                    requested_class: Some(DeliveryClass::MobilitySafe),
                    ..CallerOptions::default()
                },
                ReplySpaceRule::CallerInbox,
                19,
                Time::from_nanos(2),
            )
            .expect("mobility-safe admission");
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-transfer-class",
            "caller-a",
            "orders-origin",
            boundary.request_subject().as_str(),
            default_admission.certificate.delivery_class,
            make_task(),
            make_region(),
            Time::from_nanos(3),
            default_admission.certificate.timeout,
        )
        .expect("allocate obligation");

        let error = boundary
            .transfer_request_via_import(
                &admission,
                &mut obligation,
                ImportTransferRequest::new(
                    "orders-edge",
                    Subject::new("tenant.acme.service.edge-orders.lookup"),
                    "import/orders->edge",
                    None,
                    Time::from_nanos(4),
                ),
                &authoritative_import_morphism(),
            )
            .expect_err("delivery-class mismatch should fail closed");

        assert_eq!(
            error,
            ServiceBoundaryError::AdmissionDeliveryClassMismatch {
                admission_class: DeliveryClass::MobilitySafe,
                obligation_class: DeliveryClass::ObligationBacked,
            }
        );
        assert!(obligation.lineage.is_empty());
        assert_eq!(obligation.subject, boundary.request_subject().as_str());
    }

    #[test]
    fn service_boundary_transfer_rejects_admission_timeout_mismatch() {
        let boundary = transferable_service_boundary();
        let mut ledger = ObligationLedger::new();
        let default_admission = boundary
            .admit_request(
                "req-transfer-timeout",
                "caller-a",
                &CallerOptions::default(),
                ReplySpaceRule::CallerInbox,
                20,
                Time::from_nanos(1),
            )
            .expect("default admission");
        let admission = boundary
            .admit_request(
                "req-transfer-timeout",
                "caller-a",
                &CallerOptions {
                    timeout_override: Some(Duration::from_secs(5)),
                    ..CallerOptions::default()
                },
                ReplySpaceRule::CallerInbox,
                21,
                Time::from_nanos(2),
            )
            .expect("timed admission");
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-transfer-timeout",
            "caller-a",
            "orders-origin",
            boundary.request_subject().as_str(),
            default_admission.certificate.delivery_class,
            make_task(),
            make_region(),
            Time::from_nanos(3),
            default_admission.certificate.timeout,
        )
        .expect("allocate obligation");

        let error = boundary
            .transfer_request_via_import(
                &admission,
                &mut obligation,
                ImportTransferRequest::new(
                    "orders-edge",
                    Subject::new("tenant.acme.service.edge-orders.lookup"),
                    "import/orders->edge",
                    None,
                    Time::from_nanos(4),
                ),
                &authoritative_import_morphism(),
            )
            .expect_err("timeout mismatch should fail closed");

        assert_eq!(
            error,
            ServiceBoundaryError::AdmissionTimeoutMismatch {
                admission_timeout: Some(Duration::from_secs(5)),
                obligation_timeout: Some(Duration::from_secs(30)),
            }
        );
        assert!(obligation.lineage.is_empty());
        assert_eq!(obligation.subject, boundary.request_subject().as_str());
    }

    #[test]
    fn service_boundary_cancellation_propagates_to_service_obligation_abort() {
        let boundary = service_boundary();
        let mut ledger = ObligationLedger::new();
        let caller = CallerOptions {
            requested_class: Some(DeliveryClass::ObligationBacked),
            ..CallerOptions::default()
        };
        let admission = boundary
            .admit_request(
                "req-cancel",
                "caller-a",
                &caller,
                ReplySpaceRule::CallerInbox,
                42,
                Time::from_nanos(1),
            )
            .expect("admission");
        let obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-cancel",
            "caller-a",
            "orders-origin",
            boundary.request_subject().as_str(),
            admission.validated.delivery_class,
            make_task(),
            make_region(),
            Time::from_nanos(2),
            admission.validated.timeout,
        )
        .expect("allocate obligation");
        let obligation_id = obligation.obligation_id().expect("tracked obligation");

        let aborted = boundary
            .cancel_request(obligation, &mut ledger, Time::from_nanos(3))
            .expect("cancel request");

        assert_eq!(aborted.failure, ServiceFailure::Cancelled);
        assert_eq!(aborted.obligation_id, Some(obligation_id));
        assert_eq!(ledger.pending_count(), 0);
        let record = ledger.get(obligation_id).expect("ledger record");
        assert_eq!(record.state, ObligationState::Aborted);
        assert_eq!(record.abort_reason, Some(ObligationAbortReason::Cancel));
    }

    #[test]
    fn service_registration_rejects_provider_terms_below_contract() {
        let provider_terms = ProviderTerms {
            guaranteed_durability: DeliveryClass::DurableOrdered,
            ..provider_terms()
        };

        let err = ServiceRegistration::new("fabric.echo", contract(), provider_terms)
            .expect_err("durability floor should be enforced");

        assert_eq!(
            err,
            ServiceContractError::ProviderGuaranteeBelowContractFloor {
                guaranteed_durability: DeliveryClass::DurableOrdered,
                required_durability: DeliveryClass::ObligationBacked,
            }
        );
    }

    #[test]
    fn validate_caller_accepts_in_bounds_request() {
        let registration =
            ServiceRegistration::new("fabric.echo", contract(), provider_terms()).expect("valid");
        let caller = CallerOptions {
            requested_class: Some(DeliveryClass::MobilitySafe),
            timeout_override: Some(Duration::from_secs(5)),
            priority_hint: Some(200),
        };

        let validated = registration
            .validate_caller(&caller)
            .expect("caller request should be valid");

        assert_eq!(validated.delivery_class, DeliveryClass::MobilitySafe);
        assert_eq!(validated.timeout, Some(Duration::from_secs(5)));
        assert_eq!(validated.priority_hint, Some(200));
        assert_eq!(validated.mobility_constraint, MobilityConstraint::Pinned);
    }

    #[test]
    fn validate_caller_rejects_out_of_bounds_delivery_class() {
        let registration =
            ServiceRegistration::new("fabric.echo", contract(), provider_terms()).expect("valid");
        let caller = CallerOptions {
            requested_class: Some(DeliveryClass::ForensicReplayable),
            ..CallerOptions::default()
        };

        let err = registration
            .validate_caller(&caller)
            .expect_err("caller class should be rejected");

        assert_eq!(
            err,
            ServiceContractError::DeliveryClassPolicy(
                DeliveryClassPolicyError::RequestedClassNotAdmissible {
                    requested: DeliveryClass::ForensicReplayable,
                    default_class: DeliveryClass::ObligationBacked,
                }
            )
        );
    }

    #[test]
    fn validate_caller_rejects_timeout_override_when_disabled() {
        let mut contract = contract();
        contract.budget_semantics.allow_timeout_override = false;
        let registration =
            ServiceRegistration::new("fabric.echo", contract, provider_terms()).expect("valid");
        let caller = CallerOptions {
            timeout_override: Some(Duration::from_secs(1)),
            ..CallerOptions::default()
        };

        let err = registration
            .validate_caller(&caller)
            .expect_err("timeout override should be rejected");

        assert_eq!(err, ServiceContractError::TimeoutOverrideNotAllowed);
    }

    #[test]
    fn validate_caller_rejects_timeout_override_above_contract_default() {
        let mut contract = contract();
        contract.budget_semantics.default_timeout = Some(Duration::from_secs(5));
        let registration =
            ServiceRegistration::new("fabric.echo", contract, provider_terms()).expect("valid");
        let caller = CallerOptions {
            timeout_override: Some(Duration::from_secs(6)),
            ..CallerOptions::default()
        };

        let err = registration
            .validate_caller(&caller)
            .expect_err("timeout override should stay within the provider default");

        assert_eq!(
            err,
            ServiceContractError::TimeoutOverrideExceedsDefault {
                requested_timeout: Duration::from_secs(6),
                default_timeout: Duration::from_secs(5),
            }
        );
    }

    #[test]
    fn validate_caller_accepts_timeout_override_equal_to_contract_default() {
        let mut contract = contract();
        contract.budget_semantics.default_timeout = Some(Duration::from_secs(5));
        let registration =
            ServiceRegistration::new("fabric.echo", contract, provider_terms()).expect("valid");
        let caller = CallerOptions {
            timeout_override: Some(Duration::from_secs(5)),
            ..CallerOptions::default()
        };

        let validated = registration
            .validate_caller(&caller)
            .expect("equal timeout override should remain admissible");

        assert_eq!(validated.timeout, Some(Duration::from_secs(5)));
    }

    #[test]
    fn ephemeral_request_reply_stays_untracked() {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-ephemeral",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::EphemeralInteractive,
            make_task(),
            make_region(),
            Time::from_nanos(1),
            Some(Duration::from_secs(5)),
        )
        .expect("ephemeral path should be valid");

        assert!(!obligation.is_tracked());
        assert_eq!(ledger.pending_count(), 0);

        let reply = obligation
            .commit_with_reply(
                &mut ledger,
                Time::from_nanos(2),
                b"ok".to_vec(),
                AckKind::Accepted,
                false,
            )
            .expect("cheap path commit should succeed");

        assert_eq!(reply.service_obligation_id, None);
        assert!(reply.reply_obligation.is_none());
        assert_eq!(ledger.pending_count(), 0);
    }

    #[test]
    fn obligation_backed_request_commits_and_creates_reply_obligation() {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-1",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::MobilitySafe,
            make_task(),
            make_region(),
            Time::from_nanos(10),
            Some(Duration::from_secs(5)),
        )
        .expect("tracked request should allocate");

        let service_id = obligation.obligation_id().expect("tracked obligation id");
        assert_eq!(ledger.pending_count(), 1);

        let committed = obligation
            .commit_with_reply(
                &mut ledger,
                Time::from_nanos(20),
                b"payload".to_vec(),
                AckKind::Received,
                true,
            )
            .expect("tracked commit should succeed");

        assert_eq!(committed.service_obligation_id, Some(service_id));
        assert_eq!(committed.payload, b"payload".to_vec());
        let reply = committed
            .reply_obligation
            .expect("reply obligation expected");
        let reply_id = reply.obligation_id();
        assert_eq!(reply.service_obligation_id, service_id);
        assert_eq!(ledger.pending_count(), 1);

        let delivery = reply.commit_delivery(&mut ledger, Time::from_nanos(30));
        assert_eq!(delivery.obligation_id, reply_id);
        assert_eq!(delivery.service_obligation_id, service_id);
        assert_eq!(delivery.delivery_boundary, AckKind::Received);
        assert_eq!(ledger.pending_count(), 0);
    }

    #[test]
    fn service_obligation_abort_records_typed_failure() {
        let mut ledger = ObligationLedger::new();
        let obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-2",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::ObligationBacked,
            make_task(),
            make_region(),
            Time::from_nanos(5),
            Some(Duration::from_secs(5)),
        )
        .expect("tracked request should allocate");
        let obligation_id = obligation.obligation_id().expect("tracked id");

        let aborted = obligation
            .abort(
                &mut ledger,
                Time::from_nanos(15),
                ServiceFailure::ApplicationError,
            )
            .expect("abort should succeed");

        assert_eq!(aborted.obligation_id, Some(obligation_id));
        assert_eq!(aborted.failure, ServiceFailure::ApplicationError);
        assert_eq!(ledger.pending_count(), 0);
        let record = ledger.get(obligation_id).expect("ledger record exists");
        assert_eq!(record.state, ObligationState::Aborted);
        assert_eq!(record.abort_reason, Some(ObligationAbortReason::Error));
    }

    #[test]
    fn service_obligation_transfer_preserves_identity_and_lineage() {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-3",
            "caller",
            "callee-a",
            "svc.echo",
            DeliveryClass::ObligationBacked,
            make_task(),
            make_region(),
            Time::from_nanos(1),
            Some(Duration::from_secs(5)),
        )
        .expect("tracked request should allocate");
        let obligation_id = obligation.obligation_id().expect("tracked id");

        obligation
            .transfer(
                "callee-b",
                "svc.echo.imported",
                "import/orders->edge",
                Time::from_nanos(2),
            )
            .expect("transfer should succeed");

        assert_eq!(obligation.obligation_id(), Some(obligation_id));
        assert_eq!(obligation.callee, "callee-b");
        assert_eq!(obligation.subject, "svc.echo.imported");
        assert_eq!(obligation.lineage.len(), 1);
        assert_eq!(obligation.lineage[0].morphism, "import/orders->edge");
    }

    #[test]
    fn invalid_transfer_preserves_tracked_obligation() {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-transfer-invalid",
            "caller",
            "callee-a",
            "svc.echo",
            DeliveryClass::ObligationBacked,
            make_task(),
            make_region(),
            Time::from_nanos(1),
            Some(Duration::from_secs(5)),
        )
        .expect("tracked request should allocate");
        let obligation_id = obligation.obligation_id().expect("tracked id");

        let err = obligation
            .transfer(
                "",
                "svc.echo.imported",
                "import/orders->edge",
                Time::from_nanos(2),
            )
            .expect_err("invalid transfer should be rejected");

        assert_eq!(
            err,
            ServiceObligationError::EmptyField {
                field: "transfer.callee",
            }
        );
        assert_eq!(obligation.obligation_id(), Some(obligation_id));
        assert_eq!(ledger.pending_count(), 1);
        obligation
            .abort(
                &mut ledger,
                Time::from_nanos(3),
                ServiceFailure::ApplicationError,
            )
            .expect("abort should succeed");
        assert_eq!(ledger.pending_count(), 0);
    }

    #[test]
    fn service_obligation_timeout_is_explicit_abort() {
        let mut ledger = ObligationLedger::new();
        let obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-4",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::ObligationBacked,
            make_task(),
            make_region(),
            Time::from_nanos(3),
            Some(Duration::from_secs(1)),
        )
        .expect("tracked request should allocate");
        let obligation_id = obligation.obligation_id().expect("tracked id");

        let timed_out = obligation
            .timeout(&mut ledger, Time::from_nanos(100))
            .expect("timeout should abort successfully");

        assert_eq!(timed_out.failure, ServiceFailure::TimedOut);
        let record = ledger.get(obligation_id).expect("ledger record exists");
        assert_eq!(record.state, ObligationState::Aborted);
        assert_eq!(record.abort_reason, Some(ObligationAbortReason::Explicit));
        assert_eq!(ledger.pending_count(), 0);
    }

    #[test]
    fn resolved_service_obligation_rejects_second_resolution() {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-resolved-twice",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::ObligationBacked,
            make_task(),
            make_region(),
            Time::from_nanos(1),
            Some(Duration::from_secs(5)),
        )
        .expect("tracked request should allocate");

        let committed = obligation
            .commit_with_reply(
                &mut ledger,
                Time::from_nanos(2),
                b"payload".to_vec(),
                AckKind::Served,
                false,
            )
            .expect("first resolution should succeed");

        assert!(committed.reply_obligation.is_none());
        assert_eq!(ledger.pending_count(), 0);
        let err = obligation
            .commit_with_reply(
                &mut ledger,
                Time::from_nanos(3),
                b"payload".to_vec(),
                AckKind::Served,
                false,
            )
            .expect_err("resolved obligation should reject a second commit");

        assert_eq!(
            err,
            ServiceObligationError::AlreadyResolved {
                operation: "commit_with_reply",
            }
        );
    }

    #[test]
    fn resolved_service_obligation_rejects_abort_after_commit() {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-resolved-abort",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::ObligationBacked,
            make_task(),
            make_region(),
            Time::from_nanos(1),
            Some(Duration::from_secs(5)),
        )
        .expect("tracked request should allocate");

        obligation
            .commit_with_reply(
                &mut ledger,
                Time::from_nanos(2),
                b"payload".to_vec(),
                AckKind::Served,
                false,
            )
            .expect("first resolution should succeed");

        let err = obligation
            .abort(
                &mut ledger,
                Time::from_nanos(3),
                ServiceFailure::ApplicationError,
            )
            .expect_err("resolved obligation should reject abort");

        assert_eq!(
            err,
            ServiceObligationError::AlreadyResolved { operation: "abort" }
        );
    }

    #[test]
    fn resolved_service_obligation_rejects_timeout_after_commit() {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-resolved-timeout",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::ObligationBacked,
            make_task(),
            make_region(),
            Time::from_nanos(1),
            Some(Duration::from_secs(5)),
        )
        .expect("tracked request should allocate");

        obligation
            .commit_with_reply(
                &mut ledger,
                Time::from_nanos(2),
                b"payload".to_vec(),
                AckKind::Served,
                false,
            )
            .expect("first resolution should succeed");

        let err = obligation
            .timeout(&mut ledger, Time::from_nanos(3))
            .expect_err("resolved obligation should reject timeout");

        assert_eq!(
            err,
            ServiceObligationError::AlreadyResolved {
                operation: "timeout",
            }
        );
    }

    #[test]
    fn tracked_reply_boundary_below_minimum_preserves_obligation() {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-boundary-floor",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::MobilitySafe,
            make_task(),
            make_region(),
            Time::from_nanos(1),
            Some(Duration::from_secs(5)),
        )
        .expect("tracked request should allocate");
        let obligation_id = obligation.obligation_id().expect("tracked id");

        let err = obligation
            .commit_with_reply(
                &mut ledger,
                Time::from_nanos(2),
                b"payload".to_vec(),
                AckKind::Committed,
                false,
            )
            .expect_err("boundary below durable floor should be rejected");

        assert_eq!(
            err,
            ServiceObligationError::ReplyBoundaryBelowMinimum {
                delivery_class: DeliveryClass::MobilitySafe,
                minimum_boundary: AckKind::Received,
                requested_boundary: AckKind::Committed,
            }
        );
        assert_eq!(obligation.obligation_id(), Some(obligation_id));
        assert_eq!(ledger.pending_count(), 1);
        let aborted = obligation
            .abort(
                &mut ledger,
                Time::from_nanos(3),
                ServiceFailure::ApplicationError,
            )
            .expect("abort should succeed");
        assert_eq!(aborted.obligation_id, Some(obligation_id));
        assert_eq!(ledger.pending_count(), 0);
    }

    #[test]
    fn receipt_required_reply_must_use_received_boundary() {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-receipt-boundary",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::EphemeralInteractive,
            make_task(),
            make_region(),
            Time::from_nanos(1),
            Some(Duration::from_secs(5)),
        )
        .expect("ephemeral request should allocate");

        let err = obligation
            .commit_with_reply(
                &mut ledger,
                Time::from_nanos(2),
                b"payload".to_vec(),
                AckKind::Served,
                true,
            )
            .expect_err("receipt-required replies must use the received boundary");

        assert_eq!(
            err,
            ServiceObligationError::ReceiptRequiresReceivedBoundary {
                requested_boundary: AckKind::Served,
            }
        );
        assert_eq!(ledger.pending_count(), 0);
    }

    #[test]
    fn untracked_delivery_class_rejects_follow_up_reply_tracking() {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-untracked-follow-up",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::EphemeralInteractive,
            make_task(),
            make_region(),
            Time::from_nanos(1),
            Some(Duration::from_secs(5)),
        )
        .expect("ephemeral request should allocate");

        let err = obligation
            .commit_with_reply(
                &mut ledger,
                Time::from_nanos(2),
                b"payload".to_vec(),
                AckKind::Received,
                false,
            )
            .expect_err("cheap path should not pretend to support tracked reply delivery");

        assert_eq!(
            err,
            ServiceObligationError::ReplyTrackingUnavailable {
                delivery_class: DeliveryClass::EphemeralInteractive,
                requested_boundary: AckKind::Received,
                receipt_required: false,
            }
        );
        assert_eq!(ledger.pending_count(), 0);
    }

    #[test]
    fn reply_obligation_abort_records_failure_and_clears_pending() {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-reply-abort",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::MobilitySafe,
            make_task(),
            make_region(),
            Time::from_nanos(10),
            Some(Duration::from_secs(5)),
        )
        .expect("tracked request should allocate");

        let committed = obligation
            .commit_with_reply(
                &mut ledger,
                Time::from_nanos(20),
                b"payload".to_vec(),
                AckKind::Received,
                true,
            )
            .expect("tracked commit should succeed");

        let reply = committed
            .reply_obligation
            .expect("reply obligation expected");
        let reply_id = reply.obligation_id();
        let aborted = reply.abort_delivery(
            &mut ledger,
            Time::from_nanos(30),
            ServiceFailure::TransportError,
        );

        assert_eq!(aborted.obligation_id, reply_id);
        assert_eq!(aborted.failure, ServiceFailure::TransportError);
        assert_eq!(aborted.delivery_boundary, AckKind::Received);
        let record = ledger.get(reply_id).expect("reply record exists");
        assert_eq!(record.state, ObligationState::Aborted);
        assert_eq!(record.abort_reason, Some(ObligationAbortReason::Error));
        assert_eq!(ledger.pending_count(), 0);
    }

    #[test]
    fn reply_obligation_timeout_is_explicit_abort() {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-reply-timeout",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::MobilitySafe,
            make_task(),
            make_region(),
            Time::from_nanos(10),
            Some(Duration::from_secs(5)),
        )
        .expect("tracked request should allocate");

        let committed = obligation
            .commit_with_reply(
                &mut ledger,
                Time::from_nanos(20),
                b"payload".to_vec(),
                AckKind::Received,
                true,
            )
            .expect("tracked commit should succeed");

        let reply = committed
            .reply_obligation
            .expect("reply obligation expected");
        let reply_id = reply.obligation_id();
        let timed_out = reply.timeout(&mut ledger, Time::from_nanos(40));

        assert_eq!(timed_out.obligation_id, reply_id);
        assert_eq!(timed_out.failure, ServiceFailure::TimedOut);
        assert_eq!(timed_out.delivery_boundary, AckKind::Received);
        let record = ledger.get(reply_id).expect("reply record exists");
        assert_eq!(record.state, ObligationState::Aborted);
        assert_eq!(record.abort_reason, Some(ObligationAbortReason::Explicit));
        assert_eq!(ledger.pending_count(), 0);
    }

    // ========================================================================
    // Comprehensive service contract tests (bead 8w83i.10.2)
    // ========================================================================

    // -- PayloadShape validation ---------------------------------------------

    #[test]
    fn payload_shape_named_schema_rejects_empty() {
        let shape = PayloadShape::NamedSchema {
            schema: "  ".to_owned(),
        };
        assert!(shape.validate("test").is_err());
    }

    #[test]
    fn payload_shape_named_schema_accepts_non_empty() {
        let shape = PayloadShape::NamedSchema {
            schema: "orders.v1".to_owned(),
        };
        assert!(shape.validate("test").is_ok());
    }

    #[test]
    fn payload_shape_non_named_variants_validate() {
        for shape in [
            PayloadShape::Empty,
            PayloadShape::JsonDocument,
            PayloadShape::BinaryBlob,
            PayloadShape::SubjectEncoded,
        ] {
            assert!(shape.validate("test").is_ok());
        }
    }

    // -- ReplyShape validation -----------------------------------------------

    #[test]
    fn reply_shape_none_validates() {
        assert!(ReplyShape::None.validate("test").is_ok());
    }

    #[test]
    fn reply_shape_unary_with_empty_named_schema_rejects() {
        let shape = ReplyShape::Unary {
            shape: PayloadShape::NamedSchema {
                schema: String::new(),
            },
        };
        assert!(shape.validate("test").is_err());
    }

    #[test]
    fn reply_shape_stream_validates_inner_shape() {
        let shape = ReplyShape::Stream {
            shape: PayloadShape::JsonDocument,
        };
        assert!(shape.validate("test").is_ok());
    }

    // -- BudgetSemantics validation ------------------------------------------

    #[test]
    fn budget_semantics_rejects_zero_timeout() {
        let budget = BudgetSemantics {
            default_timeout: Some(Duration::ZERO),
            ..BudgetSemantics::default()
        };
        match budget.validate() {
            Err(ServiceContractError::ZeroDuration { field }) => {
                assert!(field.contains("default_timeout"));
            }
            other => panic!("expected ZeroDuration, got {other:?}"),
        }
    }

    #[test]
    fn budget_semantics_none_timeout_validates() {
        let budget = BudgetSemantics {
            default_timeout: None,
            ..BudgetSemantics::default()
        };
        assert!(budget.validate().is_ok());
    }

    // -- MobilityConstraint satisfies ----------------------------------------

    #[test]
    fn mobility_unrestricted_satisfies_any_requirement() {
        assert!(MobilityConstraint::Unrestricted.satisfies(&MobilityConstraint::Unrestricted));
    }

    #[test]
    fn mobility_pinned_satisfies_pinned() {
        assert!(MobilityConstraint::Pinned.satisfies(&MobilityConstraint::Pinned));
    }

    #[test]
    fn mobility_pinned_satisfies_bounded_region() {
        assert!(
            MobilityConstraint::Pinned.satisfies(&MobilityConstraint::BoundedRegion {
                region: "us-east".to_owned(),
            })
        );
    }

    #[test]
    fn mobility_bounded_satisfies_same_region() {
        let constraint = MobilityConstraint::BoundedRegion {
            region: "eu-west".to_owned(),
        };
        let required = MobilityConstraint::BoundedRegion {
            region: "eu-west".to_owned(),
        };
        assert!(constraint.satisfies(&required));
    }

    #[test]
    fn mobility_bounded_does_not_satisfy_different_region() {
        let constraint = MobilityConstraint::BoundedRegion {
            region: "us-east".to_owned(),
        };
        let required = MobilityConstraint::BoundedRegion {
            region: "eu-west".to_owned(),
        };
        assert!(!constraint.satisfies(&required));
    }

    #[test]
    fn mobility_unrestricted_does_not_satisfy_bounded() {
        assert!(
            !MobilityConstraint::Unrestricted.satisfies(&MobilityConstraint::BoundedRegion {
                region: "any".to_owned(),
            })
        );
    }

    #[test]
    fn mobility_unrestricted_does_not_satisfy_pinned() {
        assert!(!MobilityConstraint::Unrestricted.satisfies(&MobilityConstraint::Pinned));
    }

    #[test]
    fn mobility_bounded_rejects_empty_region() {
        let mc = MobilityConstraint::BoundedRegion {
            region: "  ".to_owned(),
        };
        assert!(mc.validate("test").is_err());
    }

    // -- OverloadPolicy validation -------------------------------------------

    #[test]
    fn overload_queue_rejects_zero_capacity() {
        let policy = OverloadPolicy::QueueWithinBudget { max_pending: 0 };
        assert_eq!(
            policy.validate().unwrap_err(),
            ServiceContractError::InvalidQueueCapacity
        );
    }

    #[test]
    fn overload_queue_accepts_nonzero_capacity() {
        let policy = OverloadPolicy::QueueWithinBudget { max_pending: 100 };
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn overload_non_queue_variants_validate() {
        for policy in [
            OverloadPolicy::RejectNew,
            OverloadPolicy::DropEphemeral,
            OverloadPolicy::FailFast,
        ] {
            assert!(policy.validate().is_ok());
        }
    }

    // -- ServiceContractSchema validation ------------------------------------

    #[test]
    fn default_contract_schema_validates() {
        assert!(ServiceContractSchema::default().validate().is_ok());
    }

    #[test]
    fn contract_schema_rejects_invalid_overload_policy() {
        let mut schema = ServiceContractSchema::default();
        schema.overload_policy = OverloadPolicy::QueueWithinBudget { max_pending: 0 };
        assert!(schema.validate().is_err());
    }

    // -- ProviderTerms validation against contract ---------------------------

    #[test]
    fn provider_terms_reject_compensation_below_contract() {
        let provider = ProviderTerms {
            compensation_policy: CompensationSemantics::None,
            ..provider_terms()
        };
        let err = provider.validate_against(&contract()).unwrap_err();
        assert!(matches!(
            err,
            ServiceContractError::ProviderCompensationBelowContract { .. }
        ));
    }

    #[test]
    fn provider_terms_reject_evidence_below_contract() {
        let c = ServiceContractSchema {
            evidence_requirements: EvidenceLevel::Forensic,
            ..contract()
        };
        let provider = ProviderTerms {
            evidence_level: EvidenceLevel::Standard,
            ..provider_terms()
        };
        let err = provider.validate_against(&c).unwrap_err();
        assert!(matches!(
            err,
            ServiceContractError::ProviderEvidenceBelowContract { .. }
        ));
    }

    #[test]
    fn provider_terms_reject_incompatible_mobility() {
        let c = ServiceContractSchema {
            mobility_constraints: MobilityConstraint::Pinned,
            ..contract()
        };
        let provider = ProviderTerms {
            mobility_constraint: MobilityConstraint::Unrestricted,
            ..provider_terms()
        };
        let err = provider.validate_against(&c).unwrap_err();
        assert!(matches!(
            err,
            ServiceContractError::ProviderMobilityIncompatible { .. }
        ));
    }

    // -- ServiceFailure abort_reason mapping ---------------------------------

    #[test]
    fn service_failure_maps_to_correct_abort_reasons() {
        assert_eq!(
            ServiceFailure::Cancelled.abort_reason(),
            ObligationAbortReason::Cancel
        );
        assert_eq!(
            ServiceFailure::TimedOut.abort_reason(),
            ObligationAbortReason::Explicit
        );
        assert_eq!(
            ServiceFailure::Rejected.abort_reason(),
            ObligationAbortReason::Explicit
        );
        assert_eq!(
            ServiceFailure::Overloaded.abort_reason(),
            ObligationAbortReason::Error
        );
        assert_eq!(
            ServiceFailure::TransportError.abort_reason(),
            ObligationAbortReason::Error
        );
        assert_eq!(
            ServiceFailure::ApplicationError.abort_reason(),
            ObligationAbortReason::Error
        );
    }

    // -- Display implementations ---------------------------------------------

    #[test]
    fn cleanup_urgency_display() {
        assert_eq!(format!("{}", CleanupUrgency::Background), "background");
        assert_eq!(format!("{}", CleanupUrgency::Prompt), "prompt");
        assert_eq!(format!("{}", CleanupUrgency::Immediate), "immediate");
    }

    #[test]
    fn cancellation_obligations_display() {
        assert_eq!(
            format!("{}", CancellationObligations::BestEffortDrain),
            "best-effort-drain"
        );
        assert_eq!(
            format!("{}", CancellationObligations::DrainBeforeReply),
            "drain-before-reply"
        );
        assert_eq!(
            format!("{}", CancellationObligations::DrainAndCompensate),
            "drain-and-compensate"
        );
    }

    #[test]
    fn service_failure_display() {
        assert_eq!(format!("{}", ServiceFailure::Cancelled), "cancelled");
        assert_eq!(format!("{}", ServiceFailure::TimedOut), "timed_out");
        assert_eq!(format!("{}", ServiceFailure::Overloaded), "overloaded");
    }

    // -- Serialization round-trips -------------------------------------------

    #[test]
    fn service_contract_schema_json_round_trip() {
        let schema = ServiceContractSchema::default();
        let json = serde_json::to_string(&schema).expect("serialize");
        let rt: ServiceContractSchema = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(schema, rt);
    }

    #[test]
    fn payload_shape_all_variants_json_round_trip() {
        for shape in [
            PayloadShape::Empty,
            PayloadShape::JsonDocument,
            PayloadShape::BinaryBlob,
            PayloadShape::SubjectEncoded,
            PayloadShape::NamedSchema {
                schema: "test.v1".to_owned(),
            },
        ] {
            let json = serde_json::to_string(&shape).expect("serialize");
            let rt: PayloadShape = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(shape, rt);
        }
    }

    #[test]
    fn mobility_constraint_all_variants_json_round_trip() {
        for mc in [
            MobilityConstraint::Unrestricted,
            MobilityConstraint::BoundedRegion {
                region: "us-west".to_owned(),
            },
            MobilityConstraint::Pinned,
        ] {
            let json = serde_json::to_string(&mc).expect("serialize");
            let rt: MobilityConstraint = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(mc, rt);
        }
    }

    #[test]
    fn overload_policy_all_variants_json_round_trip() {
        for policy in [
            OverloadPolicy::RejectNew,
            OverloadPolicy::QueueWithinBudget { max_pending: 50 },
            OverloadPolicy::DropEphemeral,
            OverloadPolicy::FailFast,
        ] {
            let json = serde_json::to_string(&policy).expect("serialize");
            let rt: OverloadPolicy = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(policy, rt);
        }
    }

    // -- Default enum values -------------------------------------------------

    #[test]
    fn default_enum_values_match_expected() {
        assert_eq!(PayloadShape::default(), PayloadShape::Empty);
        assert_eq!(ReplyShape::default(), ReplyShape::None);
        assert_eq!(CleanupUrgency::default(), CleanupUrgency::Prompt);
        assert_eq!(
            CancellationObligations::default(),
            CancellationObligations::DrainBeforeReply
        );
        assert_eq!(
            CompensationSemantics::default(),
            CompensationSemantics::None
        );
        assert_eq!(
            MobilityConstraint::default(),
            MobilityConstraint::Unrestricted
        );
        assert_eq!(EvidenceLevel::default(), EvidenceLevel::Standard);
        assert_eq!(OverloadPolicy::default(), OverloadPolicy::RejectNew);
    }

    // -- Previously existing tests below ------------------------------------

    #[test]
    fn unresolved_service_obligation_is_visible_to_leak_checks() {
        let mut ledger = ObligationLedger::new();
        let obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-5",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::ObligationBacked,
            make_task(),
            make_region(),
            Time::from_nanos(3),
            Some(Duration::from_secs(1)),
        )
        .expect("tracked request should allocate");
        let obligation_id = obligation.obligation_id().expect("tracked id");

        let leaks = ledger.check_leaks();

        assert!(!leaks.is_clean());
        assert_eq!(ledger.pending_count(), 1);
        assert!(leaks.leaked.iter().any(|entry| entry.id == obligation_id));
        drop(obligation);
    }

    // ── RequestCertificate tests ────────────────────────────────────────

    #[test]
    fn request_certificate_from_validated_roundtrip() {
        let request = ValidatedServiceRequest {
            delivery_class: DeliveryClass::ObligationBacked,
            timeout: Some(Duration::from_secs(5)),
            priority_hint: None,
            guaranteed_durability: DeliveryClass::MobilitySafe,
            evidence_level: EvidenceLevel::Standard,
            mobility_constraint: MobilityConstraint::Unrestricted,
            compensation_policy: CompensationSemantics::None,
            overload_policy: OverloadPolicy::RejectNew,
        };

        let cert = RequestCertificate::from_validated(
            "req-1".into(),
            "caller-a".into(),
            "orders.region1.created".into(),
            &request,
            super::super::ir::ReplySpaceRule::CallerInbox,
            "OrderService".into(),
            0xDEAD_BEEF,
            Time::from_nanos(1000),
        );

        assert_eq!(cert.request_id, "req-1");
        assert_eq!(cert.caller, "caller-a");
        assert_eq!(cert.delivery_class, DeliveryClass::ObligationBacked);
        assert_eq!(cert.capability_fingerprint, 0xDEAD_BEEF);
        assert!(cert.validate().is_ok());
    }

    #[test]
    fn request_certificate_rejects_empty_fields() {
        let cert = RequestCertificate {
            request_id: String::new(),
            caller: "caller".into(),
            subject: "sub".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            reply_space_rule: super::super::ir::ReplySpaceRule::CallerInbox,
            service_class: "svc".into(),
            capability_fingerprint: 0,
            issued_at: Time::from_nanos(1),
            timeout: None,
        };
        assert!(cert.validate().is_err());
    }

    #[test]
    fn request_certificate_rejects_zero_timeout() {
        let cert = RequestCertificate {
            request_id: "req-1".into(),
            caller: "caller".into(),
            subject: "sub".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            reply_space_rule: super::super::ir::ReplySpaceRule::CallerInbox,
            service_class: "svc".into(),
            capability_fingerprint: 0,
            issued_at: Time::from_nanos(1),
            timeout: Some(Duration::ZERO),
        };
        assert!(matches!(
            cert.validate(),
            Err(ServiceObligationError::ZeroTimeout)
        ));
    }

    #[test]
    fn request_certificate_rejects_empty_reply_space_prefix() {
        let cert = RequestCertificate {
            request_id: "req-1".into(),
            caller: "caller".into(),
            subject: "sub".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            reply_space_rule: super::super::ir::ReplySpaceRule::SharedPrefix {
                prefix: "   ".into(),
            },
            service_class: "svc".into(),
            capability_fingerprint: 0,
            issued_at: Time::from_nanos(1),
            timeout: None,
        };
        assert_eq!(
            cert.validate(),
            Err(ServiceObligationError::EmptyField {
                field: "reply_space_rule.prefix",
            })
        );
    }

    #[test]
    fn request_certificate_digest_is_deterministic() {
        let cert = RequestCertificate {
            request_id: "req-1".into(),
            caller: "caller-a".into(),
            subject: "orders.created".into(),
            delivery_class: DeliveryClass::DurableOrdered,
            reply_space_rule: super::super::ir::ReplySpaceRule::CallerInbox,
            service_class: "OrderSvc".into(),
            capability_fingerprint: 42,
            issued_at: Time::from_nanos(1000),
            timeout: None,
        };
        assert_eq!(cert.digest(), cert.digest());
    }

    #[test]
    fn request_certificate_digest_distinguishes_reply_contract_metadata() {
        let shared = RequestCertificate {
            request_id: "req-1".into(),
            caller: "caller-a".into(),
            subject: "orders.created".into(),
            delivery_class: DeliveryClass::DurableOrdered,
            reply_space_rule: super::super::ir::ReplySpaceRule::SharedPrefix {
                prefix: "_INBOX.shared".into(),
            },
            service_class: "OrderSvc".into(),
            capability_fingerprint: 42,
            issued_at: Time::from_nanos(1000),
            timeout: Some(Duration::from_secs(5)),
        };
        let dedicated = RequestCertificate {
            reply_space_rule: super::super::ir::ReplySpaceRule::DedicatedPrefix {
                prefix: "_INBOX.dedicated".into(),
            },
            ..shared.clone()
        };

        assert_ne!(shared.digest(), dedicated.digest());
    }

    // ── ReplyCertificate tests ──────────────────────────────────────────

    #[test]
    fn reply_certificate_from_commit() {
        let commit = ServiceReplyCommit {
            request_id: "req-1".into(),
            service_obligation_id: None,
            payload: b"hello".to_vec(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            reply_obligation: None,
        };

        let cert = ReplyCertificate::from_commit(
            &commit,
            "callee-a".into(),
            Time::from_nanos(2000),
            Duration::from_millis(50),
        );

        assert_eq!(cert.request_id, "req-1");
        assert_eq!(cert.callee, "callee-a");
        assert!(!cert.is_chunked);
        assert!(cert.total_chunks.is_none());
        assert!(cert.validate().is_ok());
    }

    #[test]
    fn reply_certificate_rejects_chunked_without_count() {
        let cert = ReplyCertificate {
            request_id: "req-1".into(),
            callee: "callee-a".into(),
            delivery_class: DeliveryClass::DurableOrdered,
            service_obligation_id: None,
            payload_digest: 0,
            is_chunked: true,
            total_chunks: None,
            issued_at: Time::from_nanos(1),
            service_latency: Duration::from_millis(1),
        };
        assert!(matches!(
            cert.validate(),
            Err(ServiceObligationError::ChunkedReplyMissingCount)
        ));
    }

    #[test]
    fn reply_certificate_rejects_unary_chunk_count() {
        let cert = ReplyCertificate {
            request_id: "req-1".into(),
            callee: "callee-a".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            service_obligation_id: None,
            payload_digest: 0,
            is_chunked: false,
            total_chunks: Some(1),
            issued_at: Time::from_nanos(1),
            service_latency: Duration::from_millis(1),
        };
        assert!(matches!(
            cert.validate(),
            Err(ServiceObligationError::UnaryReplyChunkCountPresent)
        ));
    }

    #[test]
    fn reply_certificate_rejects_tracked_class_without_service_obligation_id() {
        let cert = ReplyCertificate {
            request_id: "req-1".into(),
            callee: "callee-a".into(),
            delivery_class: DeliveryClass::ObligationBacked,
            service_obligation_id: None,
            payload_digest: 0,
            is_chunked: false,
            total_chunks: None,
            issued_at: Time::from_nanos(1),
            service_latency: Duration::from_millis(1),
        };
        assert!(matches!(
            cert.validate(),
            Err(
                ServiceObligationError::TrackedReplyMissingParentObligationId {
                    delivery_class: DeliveryClass::ObligationBacked,
                }
            )
        ));
    }

    #[test]
    fn reply_certificate_digest_is_deterministic() {
        let cert = ReplyCertificate {
            request_id: "req-1".into(),
            callee: "callee-a".into(),
            delivery_class: DeliveryClass::DurableOrdered,
            service_obligation_id: None,
            payload_digest: 0xCAFE,
            is_chunked: false,
            total_chunks: None,
            issued_at: Time::from_nanos(1000),
            service_latency: Duration::from_millis(10),
        };
        assert_eq!(cert.digest(), cert.digest());
    }

    #[test]
    fn reply_certificate_digest_distinguishes_chunk_metadata() {
        let unary = ReplyCertificate {
            request_id: "req-1".into(),
            callee: "callee-a".into(),
            delivery_class: DeliveryClass::DurableOrdered,
            service_obligation_id: Some(ObligationId::new_for_test(7, 0)),
            payload_digest: 0xCAFE,
            is_chunked: false,
            total_chunks: None,
            issued_at: Time::from_nanos(1000),
            service_latency: Duration::from_millis(10),
        };
        let chunked = ReplyCertificate {
            is_chunked: true,
            total_chunks: Some(3),
            ..unary.clone()
        };

        assert_ne!(unary.digest(), chunked.digest());
    }

    // ── ChunkedReplyObligation tests ────────────────────────────────────

    #[test]
    fn chunked_reply_lifecycle_bounded() {
        let mut chunked = ChunkedReplyObligation::new(
            "family-1".into(),
            "req-1".into(),
            None,
            Some(3),
            DeliveryClass::DurableOrdered,
            AckKind::Recoverable,
        )
        .unwrap();

        assert!(!chunked.is_complete());
        assert_eq!(chunked.receive_chunk().unwrap(), 0);
        assert_eq!(chunked.receive_chunk().unwrap(), 1);
        assert!(!chunked.is_complete());
        assert_eq!(chunked.receive_chunk().unwrap(), 2);
        assert!(chunked.is_complete());

        // Fourth chunk should overflow
        assert!(matches!(
            chunked.receive_chunk(),
            Err(ServiceObligationError::ChunkedReplyOverflow {
                expected: 3,
                received: 4,
            })
        ));

        let count = chunked.finalize().unwrap();
        assert_eq!(count, 3);
        assert!(chunked.is_finalized());
    }

    #[test]
    fn chunked_reply_unbounded_stream() {
        let mut chunked = ChunkedReplyObligation::new(
            "family-2".into(),
            "req-2".into(),
            Some(ObligationId::new_for_test(21, 0)),
            None, // unbounded
            DeliveryClass::ObligationBacked,
            AckKind::Served,
        )
        .unwrap();

        for _ in 0..100 {
            chunked.receive_chunk().unwrap();
        }
        assert!(!chunked.is_complete()); // unbounded never reports complete
        assert_eq!(chunked.received_chunks(), 100);

        let count = chunked.finalize().unwrap();
        assert_eq!(count, 100);
    }

    #[test]
    fn chunked_reply_rejects_zero_expected() {
        assert!(matches!(
            ChunkedReplyObligation::new(
                "family-3".into(),
                "req-3".into(),
                None,
                Some(0),
                DeliveryClass::DurableOrdered,
                AckKind::Recoverable,
            ),
            Err(ServiceObligationError::ChunkedReplyZeroExpected)
        ));
    }

    #[test]
    fn chunked_reply_finalize_is_idempotent_guard() {
        let mut chunked = ChunkedReplyObligation::new(
            "family-4".into(),
            "req-4".into(),
            None,
            Some(1),
            DeliveryClass::EphemeralInteractive,
            AckKind::Accepted,
        )
        .unwrap();

        chunked.receive_chunk().unwrap();
        chunked.finalize().unwrap();

        // Second finalize should fail
        assert!(matches!(
            chunked.finalize(),
            Err(ServiceObligationError::AlreadyResolved { .. })
        ));
    }

    #[test]
    fn chunked_reply_certificate_carries_chunk_count() {
        let mut chunked = ChunkedReplyObligation::new(
            "family-5".into(),
            "req-5".into(),
            None,
            Some(2),
            DeliveryClass::DurableOrdered,
            AckKind::Recoverable,
        )
        .unwrap();

        chunked.receive_chunk().unwrap();
        chunked.receive_chunk().unwrap();
        chunked.finalize().unwrap();

        let cert = chunked
            .certificate(
                "callee-a".into(),
                0xBEEF,
                Time::from_nanos(3000),
                Duration::from_millis(100),
            )
            .expect("finalized bounded stream should produce a certificate");

        assert!(cert.is_chunked);
        assert_eq!(cert.total_chunks, Some(2));
        assert_eq!(cert.payload_digest, 0xBEEF);
        assert!(cert.validate().is_ok());
    }

    #[test]
    fn chunked_reply_finalize_rejects_incomplete_bounded_stream() {
        let mut chunked = ChunkedReplyObligation::new(
            "family-early-finalize".into(),
            "req-early-finalize".into(),
            None,
            Some(2),
            DeliveryClass::DurableOrdered,
            AckKind::Recoverable,
        )
        .unwrap();

        chunked.receive_chunk().unwrap();

        assert!(matches!(
            chunked.finalize(),
            Err(ServiceObligationError::ChunkedReplyIncomplete {
                expected: 2,
                received: 1,
            })
        ));
        assert!(!chunked.is_finalized());
    }

    #[test]
    fn chunked_reply_certificate_requires_finalize() {
        let mut chunked = ChunkedReplyObligation::new(
            "family-unfinalized-cert".into(),
            "req-unfinalized-cert".into(),
            None,
            Some(1),
            DeliveryClass::DurableOrdered,
            AckKind::Recoverable,
        )
        .unwrap();

        chunked.receive_chunk().unwrap();

        assert!(matches!(
            chunked.certificate(
                "callee-a".into(),
                0xCAFE,
                Time::from_nanos(1),
                Duration::from_millis(10),
            ),
            Err(ServiceObligationError::ChunkedReplyNotFinalized)
        ));
    }

    #[test]
    fn chunked_reply_receive_after_finalize_fails() {
        let mut chunked = ChunkedReplyObligation::new(
            "family-6".into(),
            "req-6".into(),
            Some(ObligationId::new_for_test(22, 0)),
            Some(1), // bounded stream — finalize is allowed once the single chunk arrives
            DeliveryClass::ObligationBacked,
            AckKind::Served,
        )
        .unwrap();

        chunked.receive_chunk().unwrap();
        chunked.finalize().unwrap();

        assert!(matches!(
            chunked.receive_chunk(),
            Err(ServiceObligationError::AlreadyResolved { .. })
        ));
    }

    #[test]
    fn chunked_reply_finalize_rejects_incomplete() {
        let mut chunked = ChunkedReplyObligation::new(
            "family-7".into(),
            "req-7".into(),
            Some(ObligationId::new_for_test(23, 0)),
            Some(5),
            DeliveryClass::ObligationBacked,
            AckKind::Served,
        )
        .unwrap();

        chunked.receive_chunk().unwrap();
        // Finalize with only 1 of 5 chunks should fail
        assert!(matches!(
            chunked.finalize(),
            Err(ServiceObligationError::ChunkedReplyIncomplete {
                expected: 5,
                received: 1,
            })
        ));
    }

    #[test]
    fn chunked_reply_rejects_boundary_below_minimum() {
        assert!(matches!(
            ChunkedReplyObligation::new(
                "family-below-min".into(),
                "req-below-min".into(),
                None,
                Some(1),
                DeliveryClass::DurableOrdered,
                AckKind::Committed,
            ),
            Err(ServiceObligationError::ReplyBoundaryBelowMinimum {
                delivery_class: DeliveryClass::DurableOrdered,
                minimum_boundary: AckKind::Recoverable,
                requested_boundary: AckKind::Committed,
            })
        ));
    }

    #[test]
    fn chunked_reply_rejects_untracked_follow_up_boundary() {
        assert!(matches!(
            ChunkedReplyObligation::new(
                "family-untracked".into(),
                "req-untracked".into(),
                None,
                Some(1),
                DeliveryClass::EphemeralInteractive,
                AckKind::Received,
            ),
            Err(ServiceObligationError::ReplyTrackingUnavailable {
                delivery_class: DeliveryClass::EphemeralInteractive,
                requested_boundary: AckKind::Received,
                receipt_required: false,
            })
        ));
    }

    #[test]
    fn chunked_reply_rejects_tracked_class_without_parent_obligation_id() {
        assert!(matches!(
            ChunkedReplyObligation::new(
                "family-tracked-missing-parent".into(),
                "req-tracked-missing-parent".into(),
                None,
                Some(1),
                DeliveryClass::ObligationBacked,
                AckKind::Served,
            ),
            Err(
                ServiceObligationError::TrackedReplyMissingParentObligationId {
                    delivery_class: DeliveryClass::ObligationBacked,
                }
            )
        ));
    }

    // ── QuantitativeContract tests ──────────────────────────────────────

    #[test]
    fn quantitative_contract_valid_interactive_slo() {
        let contract = QuantitativeContract {
            name: "order-processing-p99".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            target_latency: Duration::from_millis(50),
            target_probability: 0.999,
            retry_law: RetryLaw::None,
            monitoring_policy: MonitoringPolicy::Passive,
            record_violations: true,
        };
        assert!(contract.validate().is_ok());
        assert!(contract.latency_satisfies(Duration::from_millis(30)));
        assert!(!contract.latency_satisfies(Duration::from_millis(100)));
    }

    #[test]
    fn quantitative_contract_valid_with_fixed_retry() {
        let contract = QuantitativeContract {
            name: "durable-ack".into(),
            delivery_class: DeliveryClass::DurableOrdered,
            target_latency: Duration::from_secs(5),
            target_probability: 0.99,
            retry_law: RetryLaw::Fixed {
                interval: Duration::from_millis(500),
                max_attempts: 3,
            },
            monitoring_policy: MonitoringPolicy::Sampled {
                sampling_ratio: 0.1,
                window_size: 100,
            },
            record_violations: false,
        };
        assert!(contract.validate().is_ok());
    }

    #[test]
    fn quantitative_contract_valid_with_exponential_backoff() {
        let contract = QuantitativeContract {
            name: "obligation-backed-slo".into(),
            delivery_class: DeliveryClass::ObligationBacked,
            target_latency: Duration::from_secs(1),
            target_probability: 0.995,
            retry_law: RetryLaw::ExponentialBackoff {
                initial_delay: Duration::from_millis(100),
                multiplier: 2.0,
                max_delay: Duration::from_secs(10),
                max_attempts: 5,
            },
            monitoring_policy: MonitoringPolicy::EProcess {
                confidence: 0.99,
                max_evidence: 100.0,
            },
            record_violations: true,
        };
        assert!(contract.validate().is_ok());
    }

    #[test]
    fn quantitative_contract_valid_with_conformal_monitoring() {
        let contract = QuantitativeContract {
            name: "forensic-slo".into(),
            delivery_class: DeliveryClass::ForensicReplayable,
            target_latency: Duration::from_secs(30),
            target_probability: 0.9,
            retry_law: RetryLaw::BudgetBounded {
                interval: Duration::from_secs(1),
            },
            monitoring_policy: MonitoringPolicy::Conformal {
                target_coverage: 0.95,
                calibration_size: 50,
            },
            record_violations: true,
        };
        assert!(contract.validate().is_ok());
    }

    #[test]
    fn quantitative_contract_rejects_empty_name() {
        let contract = QuantitativeContract {
            name: String::new(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            target_latency: Duration::from_millis(50),
            target_probability: 0.999,
            retry_law: RetryLaw::None,
            monitoring_policy: MonitoringPolicy::Passive,
            record_violations: false,
        };
        assert!(matches!(
            contract.validate(),
            Err(QuantitativeContractError::EmptyName)
        ));
    }

    #[test]
    fn quantitative_contract_rejects_zero_latency() {
        let contract = QuantitativeContract {
            name: "zero-lat".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            target_latency: Duration::ZERO,
            target_probability: 0.99,
            retry_law: RetryLaw::None,
            monitoring_policy: MonitoringPolicy::Passive,
            record_violations: false,
        };
        assert!(matches!(
            contract.validate(),
            Err(QuantitativeContractError::ZeroLatency)
        ));
    }

    #[test]
    fn quantitative_contract_rejects_invalid_probability() {
        for p in [0.0, -0.1, 1.1, f64::NAN] {
            let contract = QuantitativeContract {
                name: "bad-prob".into(),
                delivery_class: DeliveryClass::EphemeralInteractive,
                target_latency: Duration::from_millis(50),
                target_probability: p,
                retry_law: RetryLaw::None,
                monitoring_policy: MonitoringPolicy::Passive,
                record_violations: false,
            };
            assert!(contract.validate().is_err(), "probability {p} should fail");
        }
    }

    #[test]
    fn quantitative_contract_rejects_bad_retry_law() {
        // Zero interval
        let contract = QuantitativeContract {
            name: "bad-retry".into(),
            delivery_class: DeliveryClass::DurableOrdered,
            target_latency: Duration::from_secs(1),
            target_probability: 0.99,
            retry_law: RetryLaw::Fixed {
                interval: Duration::ZERO,
                max_attempts: 3,
            },
            monitoring_policy: MonitoringPolicy::Passive,
            record_violations: false,
        };
        assert!(matches!(
            contract.validate(),
            Err(QuantitativeContractError::ZeroRetryInterval)
        ));

        // Zero max_attempts
        let contract = QuantitativeContract {
            name: "bad-retry".into(),
            delivery_class: DeliveryClass::DurableOrdered,
            target_latency: Duration::from_secs(1),
            target_probability: 0.99,
            retry_law: RetryLaw::Fixed {
                interval: Duration::from_millis(100),
                max_attempts: 0,
            },
            monitoring_policy: MonitoringPolicy::Passive,
            record_violations: false,
        };
        assert!(matches!(
            contract.validate(),
            Err(QuantitativeContractError::ZeroMaxAttempts)
        ));

        // Bad multiplier
        let contract = QuantitativeContract {
            name: "bad-mult".into(),
            delivery_class: DeliveryClass::DurableOrdered,
            target_latency: Duration::from_secs(1),
            target_probability: 0.99,
            retry_law: RetryLaw::ExponentialBackoff {
                initial_delay: Duration::from_millis(100),
                multiplier: 1.0,
                max_delay: Duration::from_secs(10),
                max_attempts: 3,
            },
            monitoring_policy: MonitoringPolicy::Passive,
            record_violations: false,
        };
        assert!(matches!(
            contract.validate(),
            Err(QuantitativeContractError::InvalidMultiplier(_))
        ));

        // Max delay below initial delay
        let contract = QuantitativeContract {
            name: "bad-delay-order".into(),
            delivery_class: DeliveryClass::DurableOrdered,
            target_latency: Duration::from_secs(1),
            target_probability: 0.99,
            retry_law: RetryLaw::ExponentialBackoff {
                initial_delay: Duration::from_secs(2),
                multiplier: 2.0,
                max_delay: Duration::from_secs(1),
                max_attempts: 3,
            },
            monitoring_policy: MonitoringPolicy::Passive,
            record_violations: false,
        };
        assert!(matches!(
            contract.validate(),
            Err(QuantitativeContractError::MaxDelayBelowInitialDelay {
                initial_delay,
                max_delay,
            }) if initial_delay == Duration::from_secs(2) && max_delay == Duration::from_secs(1)
        ));
    }

    #[test]
    fn quantitative_contract_rejects_bad_monitoring() {
        // Zero window
        let contract = QuantitativeContract {
            name: "bad-mon".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            target_latency: Duration::from_millis(50),
            target_probability: 0.99,
            retry_law: RetryLaw::None,
            monitoring_policy: MonitoringPolicy::Sampled {
                sampling_ratio: 0.5,
                window_size: 0,
            },
            record_violations: false,
        };
        assert!(matches!(
            contract.validate(),
            Err(QuantitativeContractError::ZeroWindowSize)
        ));

        // Bad e-process confidence
        let contract = QuantitativeContract {
            name: "bad-eproc".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            target_latency: Duration::from_millis(50),
            target_probability: 0.99,
            retry_law: RetryLaw::None,
            monitoring_policy: MonitoringPolicy::EProcess {
                confidence: 1.0,
                max_evidence: 100.0,
            },
            record_violations: false,
        };
        assert!(matches!(
            contract.validate(),
            Err(QuantitativeContractError::InvalidConfidence(_))
        ));

        // Bad conformal calibration
        let contract = QuantitativeContract {
            name: "bad-conformal".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            target_latency: Duration::from_millis(50),
            target_probability: 0.99,
            retry_law: RetryLaw::None,
            monitoring_policy: MonitoringPolicy::Conformal {
                target_coverage: 0.95,
                calibration_size: 0,
            },
            record_violations: false,
        };
        assert!(matches!(
            contract.validate(),
            Err(QuantitativeContractError::ZeroCalibrationSize)
        ));
    }

    #[test]
    fn quantitative_contract_rejects_non_finite_float_parameters() {
        let bad_multiplier = QuantitativeContract {
            name: "bad-multiplier".into(),
            delivery_class: DeliveryClass::DurableOrdered,
            target_latency: Duration::from_secs(1),
            target_probability: 0.99,
            retry_law: RetryLaw::ExponentialBackoff {
                initial_delay: Duration::from_millis(100),
                multiplier: f64::NAN,
                max_delay: Duration::from_secs(10),
                max_attempts: 3,
            },
            monitoring_policy: MonitoringPolicy::Passive,
            record_violations: false,
        };
        assert!(matches!(
            bad_multiplier.validate(),
            Err(QuantitativeContractError::InvalidMultiplier(value)) if value.is_nan()
        ));

        let bad_sampling_ratio = QuantitativeContract {
            name: "bad-sampling".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            target_latency: Duration::from_millis(50),
            target_probability: 0.99,
            retry_law: RetryLaw::None,
            monitoring_policy: MonitoringPolicy::Sampled {
                sampling_ratio: f64::NAN,
                window_size: 10,
            },
            record_violations: false,
        };
        assert!(matches!(
            bad_sampling_ratio.validate(),
            Err(QuantitativeContractError::InvalidSamplingRatio(value)) if value.is_nan()
        ));

        let bad_max_evidence = QuantitativeContract {
            name: "bad-evidence".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            target_latency: Duration::from_millis(50),
            target_probability: 0.99,
            retry_law: RetryLaw::None,
            monitoring_policy: MonitoringPolicy::EProcess {
                confidence: 0.95,
                max_evidence: f64::INFINITY,
            },
            record_violations: false,
        };
        assert!(matches!(
            bad_max_evidence.validate(),
            Err(QuantitativeContractError::ZeroMaxEvidence)
        ));

        let cap_below_threshold = QuantitativeContract {
            name: "bad-evidence-threshold".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            target_latency: Duration::from_millis(50),
            target_probability: 0.99,
            retry_law: RetryLaw::None,
            monitoring_policy: MonitoringPolicy::EProcess {
                confidence: 0.80,
                max_evidence: 4.0,
            },
            record_violations: false,
        };
        assert!(matches!(
            cap_below_threshold.validate(),
            Err(QuantitativeContractError::MaxEvidenceBelowAlertThreshold {
                max_evidence,
                threshold,
            }) if (max_evidence - 4.0).abs() < f64::EPSILON
                && (threshold - 5.0).abs() < 1e-9
        ));
    }

    #[test]
    fn quantitative_contract_uses_clamped_eprocess_threshold_near_confidence_one() {
        let confidence = f64::from_bits(1.0_f64.to_bits() - 1);
        let threshold = quantitative_eprocess_threshold(confidence);
        assert_eq!(quantitative_eprocess_alpha(confidence), f64::EPSILON);
        assert_eq!(threshold, 1.0 / f64::EPSILON);

        let contract = QuantitativeContract {
            name: "near-one-confidence".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            target_latency: Duration::from_millis(50),
            target_probability: 0.99,
            retry_law: RetryLaw::None,
            monitoring_policy: MonitoringPolicy::EProcess {
                confidence,
                max_evidence: threshold,
            },
            record_violations: false,
        };
        assert!(contract.validate().is_ok());

        let rejected = QuantitativeContract {
            monitoring_policy: MonitoringPolicy::EProcess {
                confidence,
                max_evidence: threshold / 2.0,
            },
            ..contract
        };
        assert!(matches!(
            rejected.validate(),
            Err(QuantitativeContractError::MaxEvidenceBelowAlertThreshold {
                max_evidence,
                threshold: rejected_threshold,
            }) if max_evidence == threshold / 2.0 && rejected_threshold == threshold
        ));
    }

    #[test]
    fn quantitative_contract_serde_roundtrip() {
        let contract = QuantitativeContract {
            name: "serde-test".into(),
            delivery_class: DeliveryClass::ObligationBacked,
            target_latency: Duration::from_millis(200),
            target_probability: 0.999,
            retry_law: RetryLaw::ExponentialBackoff {
                initial_delay: Duration::from_millis(50),
                multiplier: 2.0,
                max_delay: Duration::from_secs(5),
                max_attempts: 4,
            },
            monitoring_policy: MonitoringPolicy::EProcess {
                confidence: 0.99,
                max_evidence: 50.0,
            },
            record_violations: true,
        };

        let json = serde_json::to_string(&contract).expect("serialize");
        let deserialized: QuantitativeContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, deserialized);
    }

    #[test]
    fn quantitative_monitor_passive_records_policy_change_evidence() {
        let contract = QuantitativeContract {
            name: "passive-evidence".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            target_latency: Duration::from_millis(50),
            target_probability: 0.90,
            retry_law: RetryLaw::Fixed {
                interval: Duration::from_millis(10),
                max_attempts: 2,
            },
            monitoring_policy: MonitoringPolicy::Passive,
            record_violations: true,
        };
        let mut monitor = QuantitativeContractMonitor::new(contract).expect("valid monitor");
        monitor.observe_latency(Duration::from_millis(20));
        monitor.observe_latency(Duration::from_millis(70));
        let evaluation = monitor.observe_latency(Duration::from_millis(80));

        assert_eq!(evaluation.state, QuantitativeContractState::Violated);
        assert_eq!(
            evaluation.recommendation,
            QuantitativePolicyRecommendation::Escalate
        );
        let evidence = monitor
            .policy_change_evidence()
            .expect("violations should produce evidence");
        assert_eq!(evidence.contract_name, "passive-evidence");
        assert_eq!(evidence.hit_count, 1);
        assert_eq!(evidence.observations, 3);
    }

    #[test]
    fn quantitative_monitor_sampled_window_detects_violation() {
        let contract = QuantitativeContract {
            name: "sampled-window".into(),
            delivery_class: DeliveryClass::DurableOrdered,
            target_latency: Duration::from_millis(40),
            target_probability: 0.75,
            retry_law: RetryLaw::BudgetBounded {
                interval: Duration::from_millis(15),
            },
            monitoring_policy: MonitoringPolicy::Sampled {
                sampling_ratio: 1.0,
                window_size: 4,
            },
            record_violations: true,
        };
        let mut monitor = QuantitativeContractMonitor::new(contract).expect("valid monitor");
        monitor.observe_latency(Duration::from_millis(10));
        monitor.observe_latency(Duration::from_millis(20));
        monitor.observe_latency(Duration::from_millis(60));
        let evaluation = monitor.observe_latency(Duration::from_millis(70));

        assert_eq!(evaluation.state, QuantitativeContractState::Violated);
        assert_eq!(
            evaluation.recommendation,
            QuantitativePolicyRecommendation::Escalate
        );
        let QuantitativeMonitorEvidence::Sampled {
            sampled_observations,
            window_hit_rate,
            ..
        } = evaluation.evidence
        else {
            panic!("expected sampled monitoring evidence");
        };
        assert_eq!(sampled_observations, 4);
        assert!((window_hit_rate - 0.5).abs() < 1e-9);
    }

    #[test]
    fn quantitative_monitor_eprocess_alerts_and_auto_resets() {
        let contract = QuantitativeContract {
            name: "eprocess-slo".into(),
            delivery_class: DeliveryClass::ObligationBacked,
            target_latency: Duration::from_millis(10),
            target_probability: 0.95,
            retry_law: RetryLaw::Fixed {
                interval: Duration::from_millis(5),
                max_attempts: 3,
            },
            monitoring_policy: MonitoringPolicy::EProcess {
                confidence: 0.80,
                max_evidence: 10.0,
            },
            record_violations: true,
        };
        let mut monitor = QuantitativeContractMonitor::new(contract).expect("valid monitor");
        monitor.observe_latency(Duration::from_millis(100));
        monitor.observe_latency(Duration::from_millis(120));
        let evaluation = monitor.observe_latency(Duration::from_millis(150));

        assert_eq!(evaluation.state, QuantitativeContractState::Violated);
        let QuantitativeMonitorEvidence::EProcess {
            e_value,
            threshold,
            max_evidence,
            capped,
            alert_state,
            ..
        } = evaluation.evidence
        else {
            panic!("expected e-process evidence");
        };
        assert!(
            max_evidence >= threshold,
            "test config must not cap evidence below the alert threshold"
        );
        assert!(
            e_value >= threshold,
            "reported evidence should clear the alert threshold once alert_state=Alert"
        );
        assert!(capped, "e-value should cap and reset");
        assert_eq!(alert_state, QuantitativeMonitorAlertState::Alert);

        let after_reset = monitor.observe_latency(Duration::from_millis(5));
        let QuantitativeMonitorEvidence::EProcess { e_value, .. } = after_reset.evidence else {
            panic!("expected e-process evidence after reset");
        };
        assert!(
            e_value <= 1.0,
            "fresh monitor should restart from a low evidence level"
        );
    }

    #[test]
    fn quantitative_monitor_conformal_reports_drift() {
        let contract = QuantitativeContract {
            name: "conformal-slo".into(),
            delivery_class: DeliveryClass::ForensicReplayable,
            target_latency: Duration::from_millis(50),
            target_probability: 0.80,
            retry_law: RetryLaw::BudgetBounded {
                interval: Duration::from_millis(10),
            },
            monitoring_policy: MonitoringPolicy::Conformal {
                target_coverage: 0.80,
                calibration_size: 4,
            },
            record_violations: true,
        };
        let mut monitor = QuantitativeContractMonitor::new(contract).expect("valid monitor");
        for sample in [20_u64, 22, 24, 26] {
            let evaluation = monitor.observe_latency(Duration::from_millis(sample));
            assert_eq!(
                evaluation.state,
                QuantitativeContractState::Healthy,
                "calibration samples should not trigger drift by themselves"
            );
        }
        let evaluation = monitor.observe_latency(Duration::from_millis(200));

        assert_eq!(evaluation.state, QuantitativeContractState::AtRisk);
        assert_eq!(
            evaluation.recommendation,
            QuantitativePolicyRecommendation::ApplyRetryLaw
        );
        let QuantitativeMonitorEvidence::Conformal {
            calibration_samples,
            latest_conforming,
            threshold_latency,
            ..
        } = evaluation.evidence
        else {
            panic!("expected conformal evidence");
        };
        assert_eq!(calibration_samples, 4);
        assert_eq!(latest_conforming, Some(false));
        assert!(
            threshold_latency.is_some(),
            "conformal evaluation should expose the calibrated threshold"
        );
        assert!(
            monitor.policy_change_evidence().is_some(),
            "non-healthy conformal result should emit evidence when recording is enabled"
        );
    }

    #[test]
    fn quantitative_monitor_suppresses_policy_change_evidence_when_disabled() {
        let contract = QuantitativeContract {
            name: "no-evidence".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            target_latency: Duration::from_millis(30),
            target_probability: 0.99,
            retry_law: RetryLaw::None,
            monitoring_policy: MonitoringPolicy::Passive,
            record_violations: false,
        };
        let mut monitor = QuantitativeContractMonitor::new(contract).expect("valid monitor");
        monitor.observe_latency(Duration::from_millis(100));
        monitor.observe_latency(Duration::from_millis(110));
        monitor.observe_latency(Duration::from_millis(120));
        assert!(monitor.policy_change_evidence().is_none());
    }

    #[test]
    fn workflow_linear_execution_tracks_subject_steps() {
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();
        let reserve = workflow_step(
            "reserve",
            "fabric.order.reserve",
            vec![
                WorkflowObligationRole::Reply {
                    delivery_boundary: AckKind::Received,
                    receipt_required: true,
                },
                WorkflowObligationRole::Lease {
                    resource: "inventory.sku-42".to_owned(),
                },
            ],
            &[],
        );
        let settle = workflow_step(
            "settle",
            "fabric.payment.settle",
            vec![WorkflowObligationRole::Reply {
                delivery_boundary: AckKind::Received,
                receipt_required: true,
            }],
            &[],
        );
        let mut saga = SagaState::new("checkout", vec![reserve, settle]).expect("valid saga");

        saga.start_next_step(&mut ledger, task, region, Time::from_nanos(10))
            .expect("start first step");
        assert_eq!(saga.current_step, Some(0));
        let owed = saga
            .what_is_still_owed(&ledger)
            .expect("owed obligations for first step");
        assert_eq!(owed.len(), 2);
        assert!(owed.iter().all(|entry| entry.step_id == "reserve"));

        saga.complete_current_step(&mut ledger, Time::from_nanos(20))
            .expect("complete first step");
        assert_eq!(saga.steps[0].status, WorkflowStepStatus::Completed);
        assert_eq!(saga.current_step, Some(1));
        assert!(
            saga.what_is_still_owed(&ledger)
                .expect("no second-step obligations before start")
                .is_empty()
        );

        saga.start_next_step(&mut ledger, task, region, Time::from_nanos(30))
            .expect("start second step");
        let owed = saga
            .what_is_still_owed(&ledger)
            .expect("owed obligations for second step");
        assert_eq!(owed.len(), 1);
        assert_eq!(owed[0].step_id, "settle");

        saga.complete_current_step(&mut ledger, Time::from_nanos(40))
            .expect("complete second step");
        assert_eq!(saga.steps[1].status, WorkflowStepStatus::Completed);
        assert_eq!(saga.current_step, None);
        assert!(
            saga.what_is_still_owed(&ledger)
                .expect("all work should be resolved")
                .is_empty()
        );
        assert_eq!(ledger.pending_count(), 0);
    }

    #[test]
    fn workflow_failure_activates_and_commits_compensation() {
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();
        let charge = workflow_step(
            "charge",
            "fabric.payment.charge",
            vec![
                WorkflowObligationRole::Reply {
                    delivery_boundary: AckKind::Received,
                    receipt_required: true,
                },
                WorkflowObligationRole::Lease {
                    resource: "payment.intent.pi_123".to_owned(),
                },
            ],
            &["fabric.payment.refund", "fabric.inventory.restock"],
        );
        let mut saga = SagaState::new("payment-saga", vec![charge]).expect("valid saga");

        saga.start_next_step(&mut ledger, task, region, Time::from_nanos(5))
            .expect("start workflow");
        saga.fail_current_step(
            &mut ledger,
            Time::from_nanos(8),
            ServiceFailure::ApplicationError,
            task,
            region,
        )
        .expect("fail current step");

        assert_eq!(
            saga.steps[0].status,
            WorkflowStepStatus::Compensating {
                failure: ServiceFailure::ApplicationError,
            }
        );
        let owed = saga
            .what_is_still_owed(&ledger)
            .expect("compensation should now be owed");
        assert_eq!(owed.len(), 2);
        assert!(
            owed.iter()
                .all(|entry| matches!(entry.role, WorkflowObligationRole::Compensation { .. }))
        );

        saga.complete_current_compensation(&mut ledger, Time::from_nanos(13))
            .expect("commit compensation");
        assert_eq!(
            saga.steps[0].status,
            WorkflowStepStatus::Compensated {
                failure: ServiceFailure::ApplicationError,
            }
        );
        assert_eq!(saga.compensated_steps, vec!["charge".to_owned()]);
        assert!(
            saga.what_is_still_owed(&ledger)
                .expect("compensation should be resolved")
                .is_empty()
        );
        assert_eq!(ledger.pending_count(), 0);
    }

    #[test]
    fn workflow_partial_progress_tracks_only_active_step_obligations() {
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();
        let prepare = workflow_step(
            "prepare",
            "fabric.order.prepare",
            vec![WorkflowObligationRole::Reply {
                delivery_boundary: AckKind::Received,
                receipt_required: true,
            }],
            &[],
        );
        let ship = workflow_step(
            "ship",
            "fabric.order.ship",
            vec![
                WorkflowObligationRole::Reply {
                    delivery_boundary: AckKind::Received,
                    receipt_required: true,
                },
                WorkflowObligationRole::Deadline {
                    deadline: Time::from_nanos(500),
                },
            ],
            &[],
        );
        let mut saga = SagaState::new("ship-flow", vec![prepare, ship]).expect("valid saga");

        saga.start_next_step(&mut ledger, task, region, Time::from_nanos(10))
            .expect("start prepare");
        saga.complete_current_step(&mut ledger, Time::from_nanos(20))
            .expect("complete prepare");
        saga.start_next_step(&mut ledger, task, region, Time::from_nanos(30))
            .expect("start ship");

        let owed = saga
            .what_is_still_owed(&ledger)
            .expect("active step obligations");
        assert_eq!(owed.len(), 2);
        assert!(owed.iter().all(|entry| entry.step_id == "ship"));
        assert!(
            owed.iter()
                .any(|entry| matches!(entry.role, WorkflowObligationRole::Reply { .. }))
        );
        assert!(
            owed.iter()
                .any(|entry| matches!(entry.role, WorkflowObligationRole::Deadline { .. }))
        );
    }

    #[test]
    fn workflow_recovery_after_crash_preserves_explicit_owed_work() {
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();
        let replicate = workflow_step(
            "replicate",
            "fabric.repair.replicate",
            vec![
                WorkflowObligationRole::Reply {
                    delivery_boundary: AckKind::Received,
                    receipt_required: true,
                },
                WorkflowObligationRole::Timeout,
            ],
            &[],
        );
        let mut saga = SagaState::new("repair", vec![replicate]).expect("valid saga");

        saga.start_next_step(&mut ledger, task, region, Time::from_nanos(11))
            .expect("start step");
        let encoded = serde_json::to_string(&saga).expect("serialize saga snapshot");
        let snapshot: SagaState = serde_json::from_str(&encoded).expect("deserialize snapshot");

        let mut recovered = snapshot
            .recover_from_replay(&ledger, Time::from_nanos(19))
            .expect("recover from snapshot");
        assert_eq!(recovered.current_step, Some(0));
        assert!(matches!(
            recovered
                .evidence_trail
                .last()
                .expect("recovery evidence")
                .event,
            SagaEvidenceEvent::Recovered
        ));
        assert_eq!(
            recovered
                .what_is_still_owed(&ledger)
                .expect("recovered owed work")
                .len(),
            2
        );

        recovered
            .fail_current_step(
                &mut ledger,
                Time::from_nanos(25),
                ServiceFailure::TimedOut,
                task,
                region,
            )
            .expect("abort by id during recovery");
        assert_eq!(
            recovered.steps[0].status,
            WorkflowStepStatus::Failed {
                failure: ServiceFailure::TimedOut,
            }
        );
        assert!(
            recovered
                .what_is_still_owed(&ledger)
                .expect("all recovered work should be resolved")
                .is_empty()
        );
        assert_eq!(ledger.pending_count(), 0);
    }

    #[test]
    fn workflow_what_is_still_owed_excludes_future_pending_steps() {
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();
        let ingest = workflow_step(
            "ingest",
            "fabric.ingest.start",
            vec![WorkflowObligationRole::Lease {
                resource: "shard-01".to_owned(),
            }],
            &[],
        );
        let compact = workflow_step(
            "compact",
            "fabric.ingest.compact",
            vec![WorkflowObligationRole::Reply {
                delivery_boundary: AckKind::Received,
                receipt_required: true,
            }],
            &[],
        );
        let mut saga = SagaState::new("ingest-flow", vec![ingest, compact]).expect("valid saga");

        saga.start_next_step(&mut ledger, task, region, Time::from_nanos(7))
            .expect("start ingest");
        let owed = saga
            .what_is_still_owed(&ledger)
            .expect("ingest obligation should be owed");
        assert_eq!(owed.len(), 1);
        assert_eq!(owed[0].step_id, "ingest");
        assert_eq!(owed[0].state, ObligationState::Reserved);
        let record = ledger
            .get(owed[0].obligation_id)
            .expect("obligation record must exist");
        assert_eq!(record.state, ObligationState::Reserved);

        saga.complete_current_step(&mut ledger, Time::from_nanos(9))
            .expect("complete ingest");
        assert!(
            saga.what_is_still_owed(&ledger)
                .expect("future pending step should stay absent")
                .is_empty()
        );
    }

    #[test]
    fn quantitative_ratio_is_fail_closed_on_empty_window() {
        assert_eq!(ratio(0, 0), 0.0);
        assert_eq!(bool_ratio(&VecDeque::new()), 0.0);
    }
