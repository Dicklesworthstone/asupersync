    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn authoritative_morphism() -> Morphism {
        Morphism {
            source_language: SubjectPattern::new("tenant.orders"),
            dest_language: SubjectPattern::new("authority.orders"),
            class: MorphismClass::Authoritative,
            transform: SubjectTransform::RenamePrefix {
                from: SubjectPattern::new("tenant.orders"),
                to: SubjectPattern::new("authority.orders"),
            },
            reversibility: ReversibilityRequirement::Bijective,
            capability_requirements: vec![
                FabricCapability::CarryAuthority,
                FabricCapability::ReplyAuthority,
            ],
            response_policy: ResponsePolicy::ReplyAuthoritative,
            ..Morphism::default()
        }
    }

    #[test]
    fn authoritative_compile_produces_deterministic_certificate() {
        let morphism = authoritative_morphism();
        let first = morphism.compile().expect("compile certificate");
        let second = morphism.compile().expect("compile certificate twice");

        assert_eq!(first, second);
        assert_eq!(first.class, MorphismClass::Authoritative);
        assert_eq!(
            first.facets.authority.capability_requirements,
            vec![
                FabricCapability::CarryAuthority,
                FabricCapability::ReplyAuthority,
            ]
        );
    }

    #[test]
    fn authoritative_morphisms_reject_lossy_or_wildcard_rewrites() {
        let mut lossy = authoritative_morphism();
        lossy.reversibility = ReversibilityRequirement::EvidenceBacked;
        lossy.transform = SubjectTransform::RedactLiterals;
        assert_eq!(
            lossy.validate(),
            Err(MorphismValidationError::AuthoritativeTransformMustBeLossless)
        );

        let mut wildcard = authoritative_morphism();
        wildcard.transform = SubjectTransform::RenamePrefix {
            from: SubjectPattern::new("tenant.*"),
            to: SubjectPattern::new("authority.orders"),
        };
        assert_eq!(
            wildcard.validate(),
            Err(MorphismValidationError::AuthoritativeRenameMustBeLiteralOnly)
        );
    }

    #[test]
    fn delegation_requires_delegate_capability_bounded_duration_and_revocation() {
        let mut delegation = Morphism {
            class: MorphismClass::Delegation,
            response_policy: ResponsePolicy::ForwardOpaque,
            ..Morphism::default()
        };

        assert_eq!(
            delegation.validate(),
            Err(MorphismValidationError::DelegationRequiresDelegateCapability)
        );

        delegation.capability_requirements = vec![FabricCapability::DelegateNamespace];
        assert_eq!(
            delegation.validate(),
            Err(MorphismValidationError::DelegationMustBeTimeBounded)
        );

        delegation.quota_policy.max_handoff_duration = Some(Duration::from_secs(30));
        assert_eq!(
            delegation.validate(),
            Err(MorphismValidationError::DelegationMustBeRevocable)
        );

        delegation.quota_policy.revocation_required = true;
        assert!(delegation.validate().is_ok());
    }

    #[test]
    fn delegation_rejects_irreversible_and_lossy_transforms() {
        let mut delegation = Morphism {
            source_language: SubjectPattern::new("tenant.rpc"),
            dest_language: SubjectPattern::new("delegate.rpc"),
            class: MorphismClass::Delegation,
            capability_requirements: vec![FabricCapability::DelegateNamespace],
            response_policy: ResponsePolicy::ForwardOpaque,
            sharing_policy: SharingPolicy::TenantScoped,
            ..Morphism::default()
        };
        delegation.quota_policy.max_handoff_duration = Some(Duration::from_secs(30));
        delegation.quota_policy.revocation_required = true;

        delegation.reversibility = ReversibilityRequirement::Irreversible;
        assert_eq!(
            delegation.validate(),
            Err(MorphismValidationError::DelegationMustBeReversible)
        );

        delegation.reversibility = ReversibilityRequirement::EvidenceBacked;
        delegation.transform = SubjectTransform::RedactLiterals;
        assert_eq!(
            delegation.validate(),
            Err(MorphismValidationError::DelegationTransformMustBeLossless)
        );
    }

    #[test]
    fn egress_requires_stripped_replies_and_one_way_reversibility() {
        let mut egress = Morphism {
            class: MorphismClass::Egress,
            sharing_policy: SharingPolicy::Federated,
            reversibility: ReversibilityRequirement::Irreversible,
            ..Morphism::default()
        };

        assert_eq!(
            egress.validate(),
            Err(MorphismValidationError::EgressMustStripReplies)
        );

        egress.response_policy = ResponsePolicy::StripReplies;
        egress.reversibility = ReversibilityRequirement::EvidenceBacked;
        assert_eq!(
            egress.validate(),
            Err(MorphismValidationError::EgressMustBeIrreversible)
        );

        egress.reversibility = ReversibilityRequirement::Irreversible;
        egress.sharing_policy = SharingPolicy::Private;
        assert_eq!(
            egress.validate(),
            Err(MorphismValidationError::EgressMustCrossBoundary)
        );
    }

    #[test]
    fn facet_views_change_independently() {
        let base = Morphism::default();

        let mut cost_variant = base.clone();
        cost_variant.quota_policy.max_fanout = 8;
        assert_eq!(base.authority_facet(), cost_variant.authority_facet());
        assert_eq!(
            base.reversibility_facet(),
            cost_variant.reversibility_facet()
        );
        assert_eq!(base.secrecy_facet(), cost_variant.secrecy_facet());
        assert_ne!(base.cost_facet(), cost_variant.cost_facet());
        assert_eq!(
            base.observability_facet(),
            cost_variant.observability_facet()
        );

        let mut observability_variant = base.clone();
        observability_variant
            .evidence_policy
            .record_counterfactual_branches = true;
        assert_eq!(
            base.authority_facet(),
            observability_variant.authority_facet()
        );
        assert_eq!(base.cost_facet(), observability_variant.cost_facet());
        assert_ne!(
            base.observability_facet(),
            observability_variant.observability_facet()
        );
    }

    #[test]
    fn duplicate_capabilities_fail_closed() {
        let mut morphism = authoritative_morphism();
        morphism.capability_requirements = vec![
            FabricCapability::ReplyAuthority,
            FabricCapability::CarryAuthority,
            FabricCapability::ReplyAuthority,
        ];

        assert_eq!(
            morphism.validate(),
            Err(MorphismValidationError::DuplicateCapability(
                FabricCapability::ReplyAuthority
            ))
        );
    }

    #[test]
    fn derived_views_cannot_smuggle_authority_or_reply_rebinding() {
        let mut derived_view = Morphism::default();
        derived_view.capability_requirements = vec![FabricCapability::CarryAuthority];
        assert_eq!(
            derived_view.validate(),
            Err(MorphismValidationError::DerivedViewCannotRequireAuthorityCapability)
        );

        derived_view.capability_requirements = vec![FabricCapability::RewriteNamespace];
        derived_view.response_policy = ResponsePolicy::ReplyAuthoritative;
        assert_eq!(
            derived_view.validate(),
            Err(MorphismValidationError::DerivedViewCannotOriginateReplyAuthority)
        );
    }

    #[test]
    fn wildcard_capture_and_compose_apply_deterministically() {
        let tokens = vec![
            String::from("tenant"),
            String::from("orders-eu"),
            String::from("priority"),
        ];
        let transform = SubjectTransform::Compose {
            steps: vec![
                SubjectTransform::WildcardCapture { index: 2 },
                SubjectTransform::SplitSlice {
                    index: 1,
                    delimiter: String::from("-"),
                    start: 0,
                    len: 1,
                },
            ],
        };

        assert_eq!(
            transform
                .apply_tokens(&tokens)
                .expect("compose should evaluate"),
            vec![String::from("orders")]
        );
        assert!(!transform.is_invertible());
    }

    #[test]
    fn rename_prefix_and_remaining_lossy_variants_cover_expected_behavior() {
        let tokens = vec![
            String::from("tenant"),
            String::from("orders"),
            String::from("priority"),
        ];
        let rename = SubjectTransform::RenamePrefix {
            from: SubjectPattern::new("tenant.orders"),
            to: SubjectPattern::new("authority.orders"),
        };
        let rewritten = rename
            .apply_tokens(&tokens)
            .expect("rename-prefix should rewrite matching literal prefixes");
        assert_eq!(
            rewritten,
            vec![
                String::from("authority"),
                String::from("orders"),
                String::from("priority"),
            ]
        );
        assert_eq!(
            rename
                .inverse()
                .expect("literal rename should be invertible")
                .apply_tokens(&rewritten)
                .expect("inverse rename should roundtrip"),
            tokens
        );

        let redacted = SubjectTransform::RedactLiterals;
        assert_eq!(
            redacted
                .apply_tokens(&rewritten)
                .expect("redaction should preserve token count"),
            vec![String::from("_"), String::from("_"), String::from("_"),]
        );
        assert!(redacted.is_lossy());

        let summarized = SubjectTransform::SummarizeTail {
            preserve_segments: 2,
        };
        assert_eq!(
            summarized
                .apply_tokens(&rewritten)
                .expect("tail summary should preserve requested prefix"),
            vec![
                String::from("authority"),
                String::from("orders"),
                String::from("..."),
            ]
        );
        assert!(summarized.is_lossy());

        let partition = SubjectTransform::HashPartition { buckets: 8 };
        let first = partition
            .apply_tokens(&rewritten)
            .expect("hash partition should evaluate deterministically");
        let second = partition
            .apply_tokens(&rewritten)
            .expect("hash partition should remain stable");
        assert_eq!(first, second);
        let bucket = first[0]
            .parse::<u16>()
            .expect("hash partition must emit a bucket number");
        assert!(bucket < 8);
    }

    #[test]
    fn deterministic_hash_is_stable_for_selected_tokens() {
        let tokens = vec![
            String::from("tenant"),
            String::from("region"),
            String::from("user"),
        ];
        let transform = SubjectTransform::DeterministicHash {
            buckets: 32,
            source_indices: vec![1, 3],
        };

        let first = transform
            .apply_tokens(&tokens)
            .expect("hash should evaluate deterministically");
        let second = transform
            .apply_tokens(&tokens)
            .expect("hash should evaluate deterministically twice");
        assert_eq!(first, second);
    }

    #[test]
    fn transform_validation_rejects_invalid_core_parameters() {
        assert_eq!(
            SubjectTransform::SummarizeTail {
                preserve_segments: 0,
            }
            .validate(),
            Err(MorphismValidationError::SummarizeTailMustPreserveSegments)
        );
        assert_eq!(
            SubjectTransform::HashPartition { buckets: 0 }.validate(),
            Err(MorphismValidationError::HashPartitionRequiresBuckets)
        );
        assert_eq!(
            SubjectTransform::Compose { steps: Vec::new() }.validate(),
            Err(MorphismValidationError::ComposeRequiresSteps)
        );
    }

    #[test]
    fn left_and_right_extract_project_expected_substrings() {
        let tokens = vec![String::from("priority")];
        assert_eq!(
            SubjectTransform::LeftExtract { index: 1, len: 4 }
                .apply_tokens(&tokens)
                .expect("left extract should evaluate"),
            vec![String::from("prio")]
        );
        assert_eq!(
            SubjectTransform::RightExtract { index: 1, len: 4 }
                .apply_tokens(&tokens)
                .expect("right extract should evaluate"),
            vec![String::from("rity")]
        );
    }

    #[test]
    fn bijective_reversibility_rejects_irreversible_transforms() {
        let mut morphism = authoritative_morphism();
        morphism.transform = SubjectTransform::DeterministicHash {
            buckets: 16,
            source_indices: vec![1],
        };
        assert_eq!(
            morphism.validate(),
            Err(MorphismValidationError::TransformCannotSatisfyBijectiveRequirement)
        );
    }

    #[test]
    fn reversible_compose_builds_inverse_in_reverse_order() {
        let transform = SubjectTransform::Compose {
            steps: vec![
                SubjectTransform::RenamePrefix {
                    from: SubjectPattern::new("tenant.orders"),
                    to: SubjectPattern::new("authority.orders"),
                },
                SubjectTransform::Identity,
            ],
        };

        let inverse = transform.inverse().expect("compose should be invertible");
        assert_eq!(
            inverse,
            SubjectTransform::Compose {
                steps: vec![
                    SubjectTransform::Identity,
                    SubjectTransform::RenamePrefix {
                        from: SubjectPattern::new("authority.orders"),
                        to: SubjectPattern::new("tenant.orders"),
                    },
                ],
            }
        );
    }

    #[test]
    fn export_plan_compilation_attaches_certificate_capabilities_and_reply_space() {
        let mut morphism = authoritative_morphism();
        morphism.sharing_policy = SharingPolicy::Federated;
        morphism.privacy_policy.allow_cross_tenant_flow = true;

        let plan = morphism
            .compile_export_plan(None)
            .expect("export plan should compile");

        assert_eq!(plan.direction, MorphismPlanDirection::Export);
        assert_eq!(
            plan.attached_capabilities,
            vec![
                FabricCapability::CarryAuthority,
                FabricCapability::ReplyAuthority,
            ]
        );
        assert_eq!(
            plan.selected_reply_space,
            Some(ReplySpaceRule::DedicatedPrefix {
                prefix: String::from("authority.orders"),
            })
        );
        assert!(
            plan.permitted_reply_spaces
                .contains(&ReplySpaceRule::SharedPrefix {
                    prefix: String::from("authority.orders"),
                })
        );
        assert!(plan.reasoning.iter().any(|note| note.code == "reply_space"));
    }

    #[test]
    fn import_plan_compilation_defaults_forward_opaque_to_caller_inbox() {
        let mut delegation = Morphism {
            source_language: SubjectPattern::new("tenant.rpc"),
            dest_language: SubjectPattern::new("delegate.rpc"),
            class: MorphismClass::Delegation,
            capability_requirements: vec![FabricCapability::DelegateNamespace],
            response_policy: ResponsePolicy::ForwardOpaque,
            sharing_policy: SharingPolicy::TenantScoped,
            ..Morphism::default()
        };
        delegation.quota_policy.max_handoff_duration = Some(Duration::from_secs(30));
        delegation.quota_policy.revocation_required = true;
        delegation.privacy_policy.allow_cross_tenant_flow = true;

        let plan = delegation
            .compile_import_plan(None)
            .expect("import plan should compile");

        assert_eq!(plan.direction, MorphismPlanDirection::Import);
        assert_eq!(plan.selected_reply_space, Some(ReplySpaceRule::CallerInbox));
        assert_eq!(
            plan.permitted_reply_spaces,
            vec![ReplySpaceRule::CallerInbox]
        );
    }

    #[test]
    fn cross_boundary_reply_space_enforcement_rejects_unpermitted_reply_prefixes() {
        let mut morphism = Morphism {
            source_language: SubjectPattern::new("tenant.requests"),
            dest_language: SubjectPattern::new("federated.requests"),
            sharing_policy: SharingPolicy::Federated,
            ..Morphism::default()
        };
        morphism.privacy_policy.allow_cross_tenant_flow = true;

        let err = morphism
            .compile_export_plan(Some(ReplySpaceRule::DedicatedPrefix {
                prefix: String::from("reply.bad"),
            }))
            .expect_err("non-caller reply prefix should be rejected");

        assert_eq!(
            err,
            MorphismCompileError::ReplySpaceNotPermitted {
                policy: ResponsePolicy::PreserveCallerReplies,
                requested: ReplySpaceRule::DedicatedPrefix {
                    prefix: String::from("reply.bad"),
                },
                permitted: vec![ReplySpaceRule::CallerInbox],
            }
        );
    }

    #[test]
    fn cross_boundary_strip_replies_forbids_any_selected_reply_space() {
        let mut egress = Morphism {
            source_language: SubjectPattern::new("tenant.audit"),
            dest_language: SubjectPattern::new("federated.audit"),
            class: MorphismClass::Egress,
            transform: SubjectTransform::RedactLiterals,
            reversibility: ReversibilityRequirement::Irreversible,
            sharing_policy: SharingPolicy::Federated,
            response_policy: ResponsePolicy::StripReplies,
            ..Morphism::default()
        };
        egress.privacy_policy.allow_cross_tenant_flow = true;

        let err = egress
            .compile_export_plan(Some(ReplySpaceRule::CallerInbox))
            .expect_err("strip-replies egress should reject every reply space");

        assert_eq!(
            err,
            MorphismCompileError::ReplySpaceForbidden {
                policy: ResponsePolicy::StripReplies,
            }
        );
    }

    #[test]
    fn metadata_boundary_checks_fail_closed_for_public_full_disclosure() {
        let mut morphism = Morphism {
            source_language: SubjectPattern::new("tenant.audit"),
            dest_language: SubjectPattern::new("public.audit"),
            sharing_policy: SharingPolicy::PublicRead,
            ..Morphism::default()
        };
        morphism.privacy_policy.metadata_disclosure = MetadataDisclosure::Full;

        let err = morphism
            .compile_export_plan(None)
            .expect_err("public full disclosure should require explicit cross-tenant permission");

        assert_eq!(
            err,
            MorphismCompileError::MetadataBoundaryViolation {
                sharing_policy: SharingPolicy::PublicRead,
                metadata_disclosure: MetadataDisclosure::Full,
            }
        );
    }

    #[test]
    fn metadata_boundary_summary_records_redaction_and_payload_hash_evidence() {
        let mut morphism = Morphism {
            source_language: SubjectPattern::new("tenant.audit"),
            dest_language: SubjectPattern::new("federated.audit"),
            transform: SubjectTransform::RedactLiterals,
            sharing_policy: SharingPolicy::Federated,
            ..Morphism::default()
        };
        morphism.privacy_policy.allow_cross_tenant_flow = true;
        morphism.evidence_policy.record_payload_hashes = true;

        let plan = morphism
            .compile_export_plan(None)
            .expect("cross-boundary plan should compile");

        assert_eq!(
            plan.metadata_boundary,
            MetadataBoundarySummary {
                crosses_boundary: true,
                metadata_disclosure: MetadataDisclosure::Hashed,
                subject_literals_redacted: true,
                cross_tenant_flow_allowed: true,
                payload_hashes_recorded: true,
            }
        );
        assert!(plan.reasoning.iter().any(|note| {
            note.code == "metadata_boundary"
                && note.detail.contains("subject_literals_redacted=true")
                && note.detail.contains("payload_hashes_recorded=true")
        }));
    }

    #[test]
    fn semantic_cycle_detection_flags_authority_cycles() {
        let forward = authoritative_morphism();
        let reverse = Morphism {
            source_language: SubjectPattern::new("authority.orders"),
            dest_language: SubjectPattern::new("tenant.orders"),
            class: MorphismClass::Authoritative,
            transform: SubjectTransform::RenamePrefix {
                from: SubjectPattern::new("authority.orders"),
                to: SubjectPattern::new("tenant.orders"),
            },
            reversibility: ReversibilityRequirement::Bijective,
            capability_requirements: vec![
                FabricCapability::CarryAuthority,
                FabricCapability::ReplyAuthority,
            ],
            response_policy: ResponsePolicy::ReplyAuthoritative,
            ..Morphism::default()
        };

        let err = detect_semantic_cycles(&[forward, reverse])
            .expect_err("authority-bearing cycle should be rejected");

        assert!(matches!(
            err,
            MorphismCompileError::SemanticCycleDetected {
                class: SemanticCycleClass::Authority,
                ..
            }
        ));
    }

    #[test]
    fn semantic_cycle_detection_flags_irreversible_cycles() {
        let irreversible = Morphism {
            source_language: SubjectPattern::new("tenant.audit"),
            dest_language: SubjectPattern::new("egress.audit"),
            class: MorphismClass::Egress,
            transform: SubjectTransform::RedactLiterals,
            reversibility: ReversibilityRequirement::Irreversible,
            sharing_policy: SharingPolicy::Federated,
            response_policy: ResponsePolicy::StripReplies,
            ..Morphism::default()
        };
        let reverse = Morphism {
            source_language: SubjectPattern::new("egress.audit"),
            dest_language: SubjectPattern::new("tenant.audit"),
            ..Morphism::default()
        };

        let err = detect_semantic_cycles(&[irreversible, reverse])
            .expect_err("irreversible cycle should be rejected");

        assert!(matches!(
            err,
            MorphismCompileError::SemanticCycleDetected {
                class: SemanticCycleClass::Reversibility,
                ..
            }
        ));
    }

    #[test]
    fn semantic_cycle_detection_flags_capability_cycles() {
        let mut boundary = Morphism {
            source_language: SubjectPattern::new("tenant.stream"),
            dest_language: SubjectPattern::new("federated.stream"),
            capability_requirements: vec![
                FabricCapability::RewriteNamespace,
                FabricCapability::CrossBoundaryEgress,
            ],
            sharing_policy: SharingPolicy::Federated,
            ..Morphism::default()
        };
        boundary.privacy_policy.allow_cross_tenant_flow = true;
        let reverse = Morphism {
            source_language: SubjectPattern::new("federated.stream"),
            dest_language: SubjectPattern::new("tenant.stream"),
            ..Morphism::default()
        };

        let err = detect_semantic_cycles(&[boundary, reverse])
            .expect_err("boundary capability cycle should be rejected");

        assert!(matches!(
            err,
            MorphismCompileError::SemanticCycleDetected {
                class: SemanticCycleClass::Capability,
                ..
            }
        ));
    }

    #[test]
    fn semantic_cycle_detection_flags_multi_hop_boundary_cycles() {
        let mut first = Morphism {
            source_language: SubjectPattern::new("tenant.stream"),
            dest_language: SubjectPattern::new("federated.stream"),
            capability_requirements: vec![
                FabricCapability::RewriteNamespace,
                FabricCapability::CrossBoundaryEgress,
            ],
            sharing_policy: SharingPolicy::Federated,
            ..Morphism::default()
        };
        first.privacy_policy.allow_cross_tenant_flow = true;

        let mut second = Morphism {
            source_language: SubjectPattern::new("federated.stream"),
            dest_language: SubjectPattern::new("shared.stream"),
            capability_requirements: vec![FabricCapability::ObserveEvidence],
            sharing_policy: SharingPolicy::Federated,
            ..Morphism::default()
        };
        second.privacy_policy.allow_cross_tenant_flow = true;

        let third = Morphism {
            source_language: SubjectPattern::new("shared.stream"),
            dest_language: SubjectPattern::new("tenant.stream"),
            ..Morphism::default()
        };

        let err = detect_semantic_cycles(&[first, second, third])
            .expect_err("multi-hop boundary cycle should be rejected");

        assert!(matches!(
            err,
            MorphismCompileError::SemanticCycleDetected {
                class: SemanticCycleClass::Capability,
                ref path,
            } if path.len() == 3
        ));
    }

    #[test]
    fn semantic_cycle_detection_ignores_safe_private_identity_overlap() {
        let morphism = Morphism {
            source_language: SubjectPattern::new("tenant.local"),
            dest_language: SubjectPattern::new("tenant.local"),
            ..Morphism::default()
        };

        detect_semantic_cycles(&[morphism]).expect("safe private overlap should be accepted");
    }
