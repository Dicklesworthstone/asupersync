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
    fn capability_registry_matches_subject_prefixes_fail_closed() {
        let registry = FabricCapabilityRegistry::default();
        registry
            .grant(FabricCapability::Publish {
                subject: SubjectPattern::new("orders.>"),
            })
            .expect("grant should succeed");

        assert!(registry.check(&FabricCapability::Publish {
            subject: SubjectPattern::new("orders.created"),
        }));
        assert!(registry.check(&FabricCapability::Publish {
            subject: SubjectPattern::new("orders.*"),
        }));
        assert!(!registry.check(&FabricCapability::Publish {
            subject: SubjectPattern::new("orders"),
        }));
        assert!(!registry.check(&FabricCapability::Publish {
            subject: SubjectPattern::new("payments.created"),
        }));

        let fail_closed = FabricCapabilityRegistry::default();
        fail_closed
            .grant(FabricCapability::Publish {
                subject: SubjectPattern::new("orders.*"),
            })
            .expect("narrow publish grant");
        assert!(!fail_closed.check(&FabricCapability::Publish {
            subject: SubjectPattern::new("orders.created.>"),
        }));
    }

    #[test]
    fn capability_registry_revokes_by_subject_and_scope() {
        let registry = FabricCapabilityRegistry::default();
        registry
            .grant(FabricCapability::Publish {
                subject: SubjectPattern::new("orders.>"),
            })
            .expect("publish grant");
        registry
            .grant(FabricCapability::Subscribe {
                subject: SubjectPattern::new("payments.>"),
            })
            .expect("subscribe grant");
        registry
            .grant(FabricCapability::AdminControl)
            .expect("admin grant");

        assert_eq!(
            registry.revoke_by_subject(&SubjectPattern::new("orders.created")),
            1
        );
        assert!(!registry.check(&FabricCapability::Publish {
            subject: SubjectPattern::new("orders.created"),
        }));
        assert!(registry.check(&FabricCapability::Subscribe {
            subject: SubjectPattern::new("payments.captured"),
        }));
        assert_eq!(
            registry.revoke_scope(FabricCapabilityScope::AdminControl),
            1
        );
        assert!(!registry.check(&FabricCapability::AdminControl));
    }

    #[test]
    fn namespace_capability_envelope_fails_closed_across_tenants() {
        let registry = FabricCapabilityRegistry::default();
        let acme_orders = NamespaceCapabilityEnvelope::new(
            NamespaceKernel::new("acme", "orders").expect("acme orders namespace"),
        );
        let bravo_orders = NamespaceKernel::new("bravo", "orders").expect("bravo orders namespace");

        registry
            .grant(acme_orders.publish_capability())
            .expect("publish capability");
        registry
            .grant(acme_orders.capture_capability())
            .expect("capture capability");

        assert!(
            registry.check(&FabricCapability::Publish {
                subject: SubjectPattern::from(
                    &acme_orders
                        .namespace()
                        .mailbox_subject("worker-1")
                        .expect("acme mailbox"),
                ),
            })
        );
        assert!(
            !registry.check(&FabricCapability::Publish {
                subject: SubjectPattern::from(
                    &bravo_orders
                        .mailbox_subject("worker-1")
                        .expect("bravo mailbox"),
                ),
            })
        );
        assert!(registry.check(&FabricCapability::CreateStream {
            subject: acme_orders.namespace().durable_capture_pattern(),
        }));
        assert!(!registry.check(&FabricCapability::CreateStream {
            subject: bravo_orders.durable_capture_pattern(),
        }));
    }

    #[test]
    fn namespace_trust_boundary_marks_cross_tenant_rewrites() {
        let acme_orders = NamespaceCapabilityEnvelope::new(
            NamespaceKernel::new("acme", "orders").expect("acme orders namespace"),
        );
        let acme_payments = NamespaceKernel::new("acme", "payments").expect("acme payments");
        let bravo_orders = NamespaceKernel::new("bravo", "orders").expect("bravo orders");

        let local = acme_orders.trust_boundary(acme_payments);
        let foreign = acme_orders.trust_boundary(bravo_orders);

        assert!(!local.crosses_tenant_boundary());
        assert!(foreign.crosses_tenant_boundary());
        assert_eq!(
            foreign.required_transform_capability(),
            FabricCapability::TransformSpace {
                subject: acme_orders.namespace().trust_boundary_pattern(),
            }
        );
    }
