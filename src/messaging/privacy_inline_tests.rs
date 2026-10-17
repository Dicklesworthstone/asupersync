    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn summary() -> AuthoritativeMetadataSummary {
        AuthoritativeMetadataSummary {
            summary_name: "fabric.advisory".to_owned(),
            tenant: "tenant-a".to_owned(),
            subject: "orders.eu.created".to_owned(),
            message_count: 41,
            byte_count: 4096,
            error_count: 2,
            cross_tenant: false,
        }
    }

    fn ledger() -> PrivacyBudgetLedger {
        PrivacyBudgetLedger::new(5.0).expect("valid privacy budget")
    }

    fn default_policy() -> PrivacyPolicy {
        PrivacyPolicy::default()
    }

    fn full_policy() -> PrivacyPolicy {
        let mut policy = default_policy();
        policy.metadata_disclosure = MetadataDisclosure::Full;
        policy
    }

    fn pool_epoch() -> PoolEpochKeyMaterial {
        PoolEpochKeyMaterial::from_label("pool-a", 7, "pool-seed")
            .expect("pool epoch key material should derive")
    }

    fn hierarchy_spec() -> CellKeyHierarchySpec {
        CellKeyHierarchySpec {
            subgroup: SubgroupKeyContext {
                subgroup_epoch: 3,
                subgroup_roster_hash: "subgroup-roster-hash".to_owned(),
            },
            cell: CellKeyContext {
                cell_id: "cell.orders.eu".to_owned(),
                cell_epoch: 11,
                roster_hash: "cell-roster-hash".to_owned(),
                config_epoch_hash: "config-epoch-hash".to_owned(),
                cell_rekey_generation: 2,
            },
        }
    }

    #[test]
    fn full_export_without_noise_preserves_authoritative_values() {
        let mut ledger = ledger();
        let exported = export_metadata_summary(&full_policy(), &mut ledger, &summary(), 7)
            .expect("full export should succeed");

        assert_eq!(exported.summary_name, "fabric.advisory");
        assert_eq!(exported.subject_token, "orders.eu.created");
        assert_eq!(exported.tenant_token, "tenant-a");
        assert_eq!(exported.message_count, 41);
        assert_eq!(exported.byte_count, 4096);
        assert_eq!(exported.error_count, 2);
        assert_eq!(exported.message_noise, 0);
        assert_eq!(exported.byte_noise, 0);
        assert_eq!(exported.error_noise, 0);
        assert_eq!(exported.privacy_budget_spent, None);
        assert_eq!(ledger.spent_budget(), 0.0);
    }

    #[test]
    fn hashed_export_blinds_subject_and_tenant() {
        let mut ledger = ledger();
        let policy = default_policy();

        let exported = export_metadata_summary(&policy, &mut ledger, &summary(), 17)
            .expect("hashed export should succeed");

        assert_eq!(exported.disclosure, MetadataDisclosure::Hashed);
        assert!(exported.subject_token.starts_with("sha256:"));
        assert!(exported.tenant_token.starts_with("sha256:"));
        assert_ne!(exported.subject_token, "orders.eu.created");
        assert_ne!(exported.tenant_token, "tenant-a");
    }

    #[test]
    fn default_privacy_policy_uses_hashed_disclosure() {
        assert_eq!(
            default_policy().metadata_disclosure,
            MetadataDisclosure::Hashed
        );
    }

    #[test]
    fn full_export_can_redact_subject_literals() {
        let mut ledger = ledger();
        let mut policy = full_policy();
        policy.redact_subject_literals = true;

        let exported = export_metadata_summary(&policy, &mut ledger, &summary(), 3)
            .expect("redacted full export should succeed");

        assert_eq!(exported.subject_token, "*.*.*");
        assert_eq!(exported.tenant_token, "tenant-a");
    }

    #[test]
    fn cross_tenant_export_requires_policy_opt_in() {
        let mut ledger = ledger();
        let mut summary = summary();
        summary.cross_tenant = true;

        let err = export_metadata_summary(&default_policy(), &mut ledger, &summary, 5)
            .expect_err("cross-tenant export should be rejected");

        assert!(matches!(
            err,
            PrivacyExportError::CrossTenantFlowDisallowed { .. }
        ));
    }

    #[test]
    fn privacy_budget_ledger_rejects_overspend() {
        let mut ledger = PrivacyBudgetLedger::new(0.75).expect("valid small budget");
        ledger.spend(0.5).expect("first spend fits");
        let err = ledger
            .spend(0.5)
            .expect_err("second spend should exceed budget");

        assert!(matches!(err, PrivacyExportError::BudgetExhausted { .. }));
        assert_eq!(ledger.disclosures(), 1);
    }

    #[test]
    fn noised_export_is_deterministic_and_preserves_authoritative_state() {
        let original = summary();
        let mut left_ledger = ledger();
        let mut right_ledger = ledger();
        let mut policy = default_policy();
        policy.noise_budget = Some(0.5);

        let left = export_metadata_summary(&policy, &mut left_ledger, &original, 99)
            .expect("left export should succeed");
        let right = export_metadata_summary(&policy, &mut right_ledger, &original, 99)
            .expect("right export should succeed");

        assert_eq!(left, right);
        assert_eq!(left.privacy_budget_spent, Some(0.5));
        assert_eq!(left_ledger.spent_budget(), 0.5);
        assert_eq!(left_ledger.disclosures(), 1);
        assert_eq!(original.message_count, 41);
        assert_eq!(original.byte_count, 4096);
        assert_eq!(original.error_count, 2);
    }

    #[test]
    fn invalid_summary_fields_fail_closed() {
        let mut ledger = ledger();
        let mut invalid = summary();
        invalid.subject = "   ".to_owned();

        let err = export_metadata_summary(&default_policy(), &mut ledger, &invalid, 11)
            .expect_err("invalid subject should fail");

        assert_eq!(err, PrivacyExportError::EmptyField { field: "subject" });
    }

    #[test]
    fn unit_interval_stays_inside_open_bounds_for_extreme_seeds() {
        for seed in [
            0,
            1,
            2,
            0x5555_5555_5555_5555,
            0xaaaa_aaaa_aaaa_aaaa,
            u64::MAX - 1,
            u64::MAX,
        ] {
            let sample = unit_interval(seed);
            assert!(sample > 0.0, "seed {seed} should stay above zero");
            assert!(sample < 1.0, "seed {seed} should stay below one");
        }
    }

    #[test]
    fn cell_key_hierarchy_derivation_is_deterministic_and_capability_separated() {
        let left = CellKeyHierarchy::derive(&pool_epoch(), &hierarchy_spec())
            .expect("left hierarchy should derive");
        let right = CellKeyHierarchy::derive(&pool_epoch(), &hierarchy_spec())
            .expect("right hierarchy should derive");

        assert_eq!(left, right);
        assert_ne!(left.subgroup_epoch_key, left.cell_root_key);
        assert_ne!(left.cell_root_key, left.segment_key);
        assert_ne!(left.segment_key, left.symbol_wrap_key);
        assert_ne!(left.reply_space_key, left.metadata_blind_key);
        assert_ne!(left.metadata_blind_key, left.witness_wrap_key);
    }

    #[test]
    fn rotating_pool_subgroup_or_cell_changes_derived_keys() {
        let baseline = CellKeyHierarchy::derive(&pool_epoch(), &hierarchy_spec())
            .expect("baseline hierarchy should derive");

        let rotated_pool = CellKeyHierarchy::derive(
            &PoolEpochKeyMaterial::from_label("pool-a", 8, "pool-seed")
                .expect("rotated pool should derive"),
            &hierarchy_spec(),
        )
        .expect("rotated pool hierarchy should derive");
        assert_ne!(baseline.subgroup_epoch_key, rotated_pool.subgroup_epoch_key);

        let mut subgroup_rotated = hierarchy_spec();
        subgroup_rotated.subgroup.subgroup_epoch += 1;
        let subgroup_rotated = CellKeyHierarchy::derive(&pool_epoch(), &subgroup_rotated)
            .expect("rotated subgroup hierarchy should derive");
        assert_ne!(
            baseline.subgroup_epoch_key,
            subgroup_rotated.subgroup_epoch_key
        );
        assert_ne!(baseline.cell_root_key, subgroup_rotated.cell_root_key);

        let mut cell_rotated = hierarchy_spec();
        cell_rotated.cell.cell_epoch += 1;
        cell_rotated.cell.cell_rekey_generation += 1;
        let cell_rotated = CellKeyHierarchy::derive(&pool_epoch(), &cell_rotated)
            .expect("rotated cell hierarchy should derive");
        assert_ne!(baseline.cell_root_key, cell_rotated.cell_root_key);
        assert_ne!(baseline.reply_space_key, cell_rotated.reply_space_key);
    }

    #[test]
    fn witness_material_stays_narrow_and_generation_bound() {
        let hierarchy = CellKeyHierarchy::derive(&pool_epoch(), &hierarchy_spec())
            .expect("hierarchy should derive");

        let generation_one = hierarchy
            .issue_witness_material("witness-a", 1)
            .expect("generation one witness material should derive");
        let generation_two = hierarchy
            .issue_witness_material("witness-a", 2)
            .expect("generation two witness material should derive");

        assert_eq!(generation_one.cell_id, hierarchy.cell_id);
        assert_eq!(generation_one.cell_epoch, hierarchy.cell_epoch);
        assert_ne!(generation_one.wrapped_fragment_key, hierarchy.cell_root_key);
        assert_ne!(generation_one.symbol_auth_key, hierarchy.symbol_auth_key);
        assert_ne!(
            generation_one.wrapped_fragment_key,
            generation_two.wrapped_fragment_key
        );
        assert_ne!(
            generation_one.symbol_auth_key,
            generation_two.symbol_auth_key
        );
    }

    #[test]
    fn read_delegation_ticket_enforces_epoch_cacheability_and_revocation() {
        let hierarchy = CellKeyHierarchy::derive(&pool_epoch(), &hierarchy_spec())
            .expect("hierarchy should derive");
        let ticket = hierarchy
            .issue_read_delegation_ticket(&ReadDelegationSpec {
                delegate: "reader-a".to_owned(),
                issued_generation: 3,
                cacheable_until_generation: 5,
                revocation_generation: 9,
            })
            .expect("ticket should derive");

        assert_ne!(ticket.ticket_key, hierarchy.cell_root_key);
        assert_ne!(ticket.reply_space_key, hierarchy.reply_space_key);
        assert_ne!(ticket.metadata_blind_key, hierarchy.metadata_blind_key);
        assert!(ticket.is_usable_for(hierarchy.cell_epoch, 3, 9));
        assert!(!ticket.is_usable_for(hierarchy.cell_epoch + 1, 4, 8));
        assert!(!ticket.is_usable_for(hierarchy.cell_epoch, 4, 8));
        assert!(!ticket.is_usable_for(hierarchy.cell_epoch, 6, 8));
        assert!(!ticket.is_usable_for(hierarchy.cell_epoch, 4, 10));
    }

    #[test]
    fn narrowed_read_delegation_ticket_rotates_scoped_subkeys() {
        let hierarchy = CellKeyHierarchy::derive(&pool_epoch(), &hierarchy_spec())
            .expect("hierarchy should derive");
        let broad = hierarchy
            .issue_read_delegation_ticket(&ReadDelegationSpec {
                delegate: "reader-a".to_owned(),
                issued_generation: 3,
                cacheable_until_generation: 9,
                revocation_generation: 12,
            })
            .expect("broad ticket should derive");
        let narrow = hierarchy
            .issue_read_delegation_ticket(&ReadDelegationSpec {
                delegate: "reader-a".to_owned(),
                issued_generation: 3,
                cacheable_until_generation: 5,
                revocation_generation: 12,
            })
            .expect("narrow ticket should derive");

        assert_ne!(broad.ticket_key, narrow.ticket_key);
        assert_ne!(broad.reply_space_key, narrow.reply_space_key);
        assert_ne!(broad.metadata_blind_key, narrow.metadata_blind_key);
    }

    #[test]
    fn restore_scrub_rebinds_context_and_changes_replay_sensitive_keys() {
        let original_spec = hierarchy_spec();
        let scrubbed_spec = original_spec
            .scrub_for_restore(&RestoreScrubRequest {
                subgroup: SubgroupKeyContext {
                    subgroup_epoch: 4,
                    subgroup_roster_hash: "subgroup-roster-hash-restored".to_owned(),
                },
                cell: CellKeyContext {
                    cell_id: "cell.orders.eu.restored".to_owned(),
                    cell_epoch: 12,
                    roster_hash: "cell-roster-hash-restored".to_owned(),
                    config_epoch_hash: "config-epoch-hash-restored".to_owned(),
                    cell_rekey_generation: 4,
                },
            })
            .expect("restore scrub should rebind context");

        let original = CellKeyHierarchy::derive(&pool_epoch(), &original_spec)
            .expect("original hierarchy should derive");
        let scrubbed = CellKeyHierarchy::derive(&pool_epoch(), &scrubbed_spec)
            .expect("scrubbed hierarchy should derive");

        assert_ne!(original.cell_id, scrubbed.cell_id);
        assert_ne!(original.cell_epoch, scrubbed.cell_epoch);
        assert_ne!(original.cell_root_key, scrubbed.cell_root_key);
        assert_ne!(original.reply_space_key, scrubbed.reply_space_key);
        assert_ne!(original.witness_wrap_key, scrubbed.witness_wrap_key);
    }

    #[test]
    fn invalid_read_delegation_cache_window_fails_closed() {
        let hierarchy = CellKeyHierarchy::derive(&pool_epoch(), &hierarchy_spec())
            .expect("hierarchy should derive");
        let err = hierarchy
            .issue_read_delegation_ticket(&ReadDelegationSpec {
                delegate: "reader-a".to_owned(),
                issued_generation: 5,
                cacheable_until_generation: 4,
                revocation_generation: 7,
            })
            .expect_err("cacheability window must be monotone");

        assert_eq!(
            err,
            KeyHierarchyError::InvalidGenerationWindow {
                field: "cacheable_until_generation",
                start: 5,
                end: 4,
            }
        );
    }

    #[test]
    fn restore_scrub_requires_fresh_binding() {
        let spec = hierarchy_spec();
        let err = spec
            .scrub_for_restore(&RestoreScrubRequest {
                subgroup: spec.subgroup.clone(),
                cell: spec.cell.clone(),
            })
            .expect_err("restore scrub should reject unchanged cell identity");

        assert_eq!(err, KeyHierarchyError::RestoreCellIdMustChange);
    }

    #[test]
    fn restore_scrub_requires_fresh_epoch_binding() {
        let spec = hierarchy_spec();
        let err = spec
            .scrub_for_restore(&RestoreScrubRequest {
                subgroup: SubgroupKeyContext {
                    subgroup_epoch: spec.subgroup.subgroup_epoch + 1,
                    subgroup_roster_hash: "subgroup-roster-hash-restored".to_owned(),
                },
                cell: CellKeyContext {
                    cell_id: "cell.orders.eu.restored".to_owned(),
                    cell_epoch: spec.cell.cell_epoch,
                    roster_hash: "cell-roster-hash-restored".to_owned(),
                    config_epoch_hash: "config-epoch-hash-restored".to_owned(),
                    cell_rekey_generation: spec.cell.cell_rekey_generation + 1,
                },
            })
            .expect_err("restore scrub should reject unchanged cell epoch");

        assert_eq!(err, KeyHierarchyError::RestoreCellEpochMustChange);
    }
