    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::super::{EventFamily, PublishPermit};
    use super::*;
    use crate::messaging::class::DeliveryClass;
    use crate::messaging::ir::{
        CapabilityPermission, CapabilityTokenSchema, MorphismPlan, MorphismTransform,
        SubjectFamily, SubjectPattern as IrSubjectPattern,
    };

    fn test_cx() -> Cx<crate::cx::cap::All> {
        Cx::for_testing()
    }

    fn publish_schema() -> CapabilityTokenSchema {
        CapabilityTokenSchema {
            name: "fabric.route.publish".to_owned(),
            families: vec![SubjectFamily::Event],
            delivery_classes: vec![DeliveryClass::EphemeralInteractive],
            permissions: vec![CapabilityPermission::Publish],
        }
    }

    fn export_plan() -> MorphismPlan {
        MorphismPlan {
            name: "orders-export".to_owned(),
            source_pattern: IrSubjectPattern::new("orders.>"),
            target_prefix: "federated.orders".to_owned(),
            allowed_families: vec![SubjectFamily::Event, SubjectFamily::Command],
            transforms: vec![
                MorphismTransform::FilterFamily {
                    family: SubjectFamily::Event,
                },
                MorphismTransform::PreserveReplySpace,
            ],
        }
    }

    #[test]
    fn compile_export_program_rejects_non_literal_target_prefix() {
        let mut plan = export_plan();
        plan.target_prefix = "federated.>".to_owned();

        let error = RoutingProgram::compile_export(&plan, RoutingOperationKind::Publish)
            .expect_err("wildcard target prefixes must fail closed");

        assert_eq!(
            error,
            RoutingProgramCompileError::NonLiteralTargetPrefix {
                prefix: "federated.>".to_owned(),
                source: SubjectPatternError::LiteralOnlyPatternRequired("federated.>".to_owned()),
            }
        );
    }

    #[test]
    fn compile_export_program_rejects_source_pattern_without_literal_anchor() {
        let mut plan = export_plan();
        plan.source_pattern = IrSubjectPattern::new("*.orders.created");

        let error = RoutingProgram::compile_export(&plan, RoutingOperationKind::Publish)
            .expect_err("wildcard-leading source patterns must fail closed");

        assert_eq!(
            error,
            RoutingProgramCompileError::NonLiteralSourcePatternAnchor {
                pattern: "*.orders.created".to_owned(),
            }
        );
    }

    #[test]
    fn distributed_publish_route_requires_capability_and_records_audit() {
        let program = RoutingProgram::compile_export(&export_plan(), RoutingOperationKind::Publish)
            .expect("routing program");
        let cx = test_cx();
        cx.grant_fabric_capability(FabricCapability::Publish {
            subject: SubjectPattern::new("orders.created"),
        })
        .expect("publish grant");

        let route = program
            .authorize_distributed(
                &cx,
                SubjectFamily::Event,
                &RoutingRequest::Publish(Subject::new("orders.created")),
            )
            .expect("distributed route should pass");

        assert_eq!(route.destination().as_str(), "federated.orders.created");
        assert_eq!(route.audit().program(), "orders-export");
        assert_eq!(route.audit().direction(), RoutingDirection::Export);
        assert_eq!(route.audit().family(), SubjectFamily::Event);
        assert_eq!(
            route.audit().authorized_capability(),
            &FabricCapability::Publish {
                subject: SubjectPattern::new("orders.created"),
            }
        );
        assert_eq!(
            route.audit().authorization(),
            Some(&RoutingAuthorization::Distributed)
        );
        assert_eq!(route.audit().steps(), program.steps());
    }

    #[test]
    fn distributed_publish_route_denies_missing_capability() {
        let program = RoutingProgram::compile_export(&export_plan(), RoutingOperationKind::Publish)
            .expect("routing program");
        let cx = test_cx();

        let error = program
            .authorize_distributed(
                &cx,
                SubjectFamily::Event,
                &RoutingRequest::Publish(Subject::new("orders.created")),
            )
            .expect_err("missing capability must fail closed");

        assert_eq!(
            error,
            CapabilityRoutingError::CapabilityDenied {
                program: "orders-export".to_owned(),
                required: FabricCapability::Publish {
                    subject: SubjectPattern::new("orders.created"),
                },
            }
        );
    }

    #[test]
    fn distributed_publish_route_rejects_bare_prefix_for_tail_program() {
        let program = RoutingProgram::compile_export(&export_plan(), RoutingOperationKind::Publish)
            .expect("routing program");
        let cx = test_cx();
        cx.grant_fabric_capability(FabricCapability::Publish {
            subject: SubjectPattern::new("orders.>"),
        })
        .expect("publish grant");

        let error = program
            .authorize_distributed(
                &cx,
                SubjectFamily::Event,
                &RoutingRequest::Publish(Subject::new("orders")),
            )
            .expect_err("bare prefix must be outside the tail-wildcard program");

        assert_eq!(
            error,
            CapabilityRoutingError::SubjectOutsideProgram {
                program: "orders-export".to_owned(),
                source_pattern: "orders.>".to_owned(),
                requested: "orders".to_owned(),
            }
        );
    }

    #[test]
    fn in_process_and_distributed_publish_routes_are_equivalent() {
        let program = RoutingProgram::compile_export(&export_plan(), RoutingOperationKind::Publish)
            .expect("routing program");
        let cx = test_cx();
        let token: GrantedFabricToken<PublishPermit<EventFamily>> = cx
            .grant_publish_capability::<EventFamily>(
                SubjectPattern::new("orders.>"),
                &publish_schema(),
                DeliveryClass::EphemeralInteractive,
            )
            .expect("publish token");
        let request = RoutingRequest::Publish(Subject::new("orders.shipped.eu"));

        let in_process = program
            .authorize_in_process(&token, SubjectFamily::Event, &request)
            .expect("in-process route");
        let distributed = program
            .authorize_distributed(&cx, SubjectFamily::Event, &request)
            .expect("distributed route");

        assert_eq!(in_process.destination(), distributed.destination());
        assert_eq!(
            in_process.audit().authorized_capability(),
            distributed.audit().authorized_capability()
        );
        assert_eq!(in_process.audit().family(), distributed.audit().family());
        assert_eq!(
            in_process.audit().authorization(),
            Some(&RoutingAuthorization::InProcess {
                grant_id: token.grant_id(),
            })
        );
        assert_eq!(
            distributed.audit().authorization(),
            Some(&RoutingAuthorization::Distributed)
        );
    }

    #[test]
    fn family_filters_fail_closed_before_routing() {
        let program = RoutingProgram::compile_export(&export_plan(), RoutingOperationKind::Publish)
            .expect("routing program");
        let cx = test_cx();
        cx.grant_fabric_capability(FabricCapability::Publish {
            subject: SubjectPattern::new("orders.created"),
        })
        .expect("publish grant");

        let error = program
            .authorize_distributed(
                &cx,
                SubjectFamily::Command,
                &RoutingRequest::Publish(Subject::new("orders.created")),
            )
            .expect_err("filtered-out families must fail");

        assert_eq!(
            error,
            CapabilityRoutingError::UnsupportedFamily {
                program: "orders-export".to_owned(),
                family: SubjectFamily::Command,
            }
        );
    }
