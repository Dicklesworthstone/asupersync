    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn test_registration(name: &str) -> ControllerRegistration {
        ControllerRegistration {
            name: name.to_string(),
            min_version: SnapshotVersion { major: 1, minor: 0 },
            max_version: SnapshotVersion { major: 1, minor: 0 },
            required_fields: vec!["ready_queue_len".to_string(), "cancel_lane_len".to_string()],
            target_seams: vec!["AA01-SEAM-SCHED-CANCEL-STREAK".to_string()],
            initial_mode: ControllerMode::Shadow,
            proof_artifact_id: None,
            budget: ControllerBudget::default(),
        }
    }

    #[test]
    fn snapshot_version_compatibility() {
        let v1_0 = SnapshotVersion { major: 1, minor: 0 };
        let v1_1 = SnapshotVersion { major: 1, minor: 1 };
        let v2_0 = SnapshotVersion { major: 2, minor: 0 };

        assert!(v1_0.is_compatible_with(&v1_0));
        assert!(v1_1.is_compatible_with(&v1_0));
        assert!(!v1_0.is_compatible_with(&v1_1));
        assert!(!v2_0.is_compatible_with(&v1_0));
    }

    #[test]
    fn snapshot_serialization_roundtrip() {
        let snap = RuntimeKernelSnapshot::test_default(1, Time::ZERO);
        let json = serde_json::to_string(&snap).unwrap();
        let deser: RuntimeKernelSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.id, snap.id);
        assert_eq!(deser.version, snap.version);
        assert_eq!(deser.ready_queue_len, 0);
        assert_eq!(deser.worker_count, 1);
    }

    #[test]
    fn snapshot_deterministic_serialization() {
        let snap1 = RuntimeKernelSnapshot::test_default(42, Time::ZERO);
        let snap2 = RuntimeKernelSnapshot::test_default(42, Time::ZERO);
        assert_eq!(
            serde_json::to_string(&snap1).unwrap(),
            serde_json::to_string(&snap2).unwrap(),
        );
    }

    #[test]
    fn register_valid_controller() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("test-ctrl")).unwrap();
        assert_eq!(id.0, 1);
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.mode(id), Some(ControllerMode::Shadow));
    }

    #[test]
    fn reject_empty_name() {
        let mut registry = ControllerRegistry::new();
        let mut reg = test_registration("");
        reg.name = String::new();
        assert_eq!(
            registry.register(reg).unwrap_err(),
            RegistrationError::EmptyName,
        );
    }

    #[test]
    fn reject_inverted_version_range() {
        let mut registry = ControllerRegistry::new();
        let mut reg = test_registration("bad-range");
        reg.min_version = SnapshotVersion { major: 2, minor: 0 };
        reg.max_version = SnapshotVersion { major: 1, minor: 0 };
        assert_eq!(
            registry.register(reg).unwrap_err(),
            RegistrationError::InvertedVersionRange,
        );
    }

    #[test]
    fn reject_incompatible_version() {
        let mut registry = ControllerRegistry::new();
        let mut reg = test_registration("future-ctrl");
        reg.min_version = SnapshotVersion { major: 5, minor: 0 };
        reg.max_version = SnapshotVersion { major: 5, minor: 0 };
        assert!(matches!(
            registry.register(reg).unwrap_err(),
            RegistrationError::IncompatibleVersion { .. }
        ));

        // Test minor version incompatibility
        let mut reg2 = test_registration("future-minor-ctrl");
        reg2.min_version = SnapshotVersion {
            major: SNAPSHOT_VERSION.major,
            minor: SNAPSHOT_VERSION.minor + 1,
        };
        reg2.max_version = SnapshotVersion {
            major: SNAPSHOT_VERSION.major,
            minor: SNAPSHOT_VERSION.minor + 1,
        };
        assert!(matches!(
            registry.register(reg2).unwrap_err(),
            RegistrationError::IncompatibleVersion { .. }
        ));
    }

    #[test]
    fn snapshot_version_supported_enforces_upper_minor_bound() {
        let current = SnapshotVersion { major: 1, minor: 2 };
        let min = SnapshotVersion { major: 1, minor: 0 };
        let max = SnapshotVersion { major: 1, minor: 1 };

        assert!(
            !ControllerRegistry::snapshot_version_supported(current, min, max),
            "future snapshot minor versions must respect the declared max bound"
        );
    }

    #[test]
    fn reject_unsupported_fields() {
        let mut registry = ControllerRegistry::new();
        let mut reg = test_registration("bad-fields");
        reg.required_fields = vec!["nonexistent_field".to_string()];
        assert!(matches!(
            registry.register(reg).unwrap_err(),
            RegistrationError::UnsupportedFields(_)
        ));
    }

    #[test]
    fn reject_no_target_seams() {
        let mut registry = ControllerRegistry::new();
        let mut reg = test_registration("no-seams");
        reg.target_seams = vec![];
        assert_eq!(
            registry.register(reg).unwrap_err(),
            RegistrationError::NoTargetSeams,
        );
    }

    #[test]
    fn reject_zero_budget() {
        let mut registry = ControllerRegistry::new();
        let mut reg = test_registration("zero-budget");
        reg.budget.max_decisions_per_epoch = 0;
        assert_eq!(
            registry.register(reg).unwrap_err(),
            RegistrationError::ZeroBudget,
        );
    }

    #[test]
    fn reject_duplicate_name() {
        let mut registry = ControllerRegistry::new();
        registry.register(test_registration("dup")).unwrap();
        assert_eq!(
            registry.register(test_registration("dup")).unwrap_err(),
            RegistrationError::DuplicateName("dup".to_string()),
        );
    }

    #[test]
    fn deregister_controller() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("removable")).unwrap();
        assert!(registry.deregister(id));
        assert_eq!(registry.len(), 0);
        assert!(!registry.deregister(id));
    }

    #[test]
    fn set_mode() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("mode-test")).unwrap();
        assert_eq!(registry.mode(id), Some(ControllerMode::Shadow));
        assert!(registry.set_mode(id, ControllerMode::Active));
        assert_eq!(registry.mode(id), Some(ControllerMode::Active));
    }

    #[test]
    fn set_mode_resets_epoch_residency() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("mode-reset")).unwrap();
        registry.advance_epoch();
        registry.advance_epoch();
        assert_eq!(registry.epochs_in_current_mode(id), Some(2));

        assert!(registry.set_mode(id, ControllerMode::Shadow));
        assert_eq!(registry.epochs_in_current_mode(id), Some(0));

        registry.advance_epoch();
        assert_eq!(registry.epochs_in_current_mode(id), Some(1));
    }

    #[test]
    fn shadow_count() {
        let mut registry = ControllerRegistry::new();
        let id1 = registry.register(test_registration("s1")).unwrap();
        let _id2 = registry.register(test_registration("s2")).unwrap();
        assert_eq!(registry.shadow_count(), 2);
        registry.set_mode(id1, ControllerMode::Active);
        assert_eq!(registry.shadow_count(), 1);
    }

    #[test]
    fn decision_budget_enforcement() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("budget-ctrl")).unwrap();
        let snap_id = registry.next_snapshot_id();

        let decision = ControllerDecision {
            controller_id: id,
            snapshot_id: snap_id,
            label: "test".to_string(),
            payload: serde_json::Value::Null,
            confidence: 0.9,
            fallback_label: "noop".to_string(),
        };

        // First decision within budget (max_decisions_per_epoch = 1)
        assert!(registry.record_decision(&decision));
        // Second decision exceeds budget
        assert!(!registry.record_decision(&decision));
        // Reset epoch
        registry.reset_epoch();
        // First decision after reset is within budget again
        assert!(registry.record_decision(&decision));
    }

    #[test]
    fn calibration_tracking() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("calib")).unwrap();
        assert_eq!(registry.calibration_score(id), Some(0.0));
        registry.update_calibration(id, 0.85);
        assert_eq!(registry.calibration_score(id), Some(0.85));
    }

    #[test]
    fn snapshot_id_monotonic() {
        let mut registry = ControllerRegistry::new();
        let id1 = registry.next_snapshot_id();
        let id2 = registry.next_snapshot_id();
        let id3 = registry.next_snapshot_id();
        assert!(id1 < id2);
        assert!(id2 < id3);
    }

    #[test]
    fn snapshot_id_overflow_panics() {
        let mut registry = ControllerRegistry::new();
        registry.next_snapshot_id = u64::MAX;

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = registry.next_snapshot_id();
        }));
        assert!(panic.is_err(), "snapshot id overflow must panic");
    }

    #[test]
    fn active_mode_not_downgraded_when_snapshot_matches() {
        let mut registry = ControllerRegistry::new();
        let mut reg = test_registration("downgrade-test");
        reg.initial_mode = ControllerMode::Active;
        // Controller supports up to SNAPSHOT_VERSION
        reg.min_version = SNAPSHOT_VERSION;
        reg.max_version = SNAPSHOT_VERSION;
        // This should work since versions match
        let id = registry.register(reg).unwrap();
        assert_eq!(registry.mode(id), Some(ControllerMode::Active));
    }

    #[test]
    fn known_fields_completeness() {
        // Verify KNOWN_FIELDS matches snapshot struct fields
        let snap = RuntimeKernelSnapshot::test_default(1, Time::ZERO);
        let json = serde_json::to_value(&snap).unwrap();
        let obj = json.as_object().unwrap();
        // Non-data fields that aren't in KNOWN_FIELDS
        let meta_fields = [
            "id",
            "version",
            "timestamp",
            "registered_controllers",
            "shadow_controllers",
        ];
        for field in KNOWN_FIELDS {
            assert!(
                obj.contains_key(*field),
                "KNOWN_FIELDS contains '{field}' but snapshot JSON does not"
            );
        }
        for key in obj.keys() {
            if meta_fields.contains(&key.as_str()) {
                continue;
            }
            assert!(
                KNOWN_FIELDS.contains(&key.as_str()),
                "snapshot JSON has field '{key}' not in KNOWN_FIELDS"
            );
        }
    }

    #[test]
    fn registration_info_accessible() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("info-test")).unwrap();
        let reg = registry.registration(id).unwrap();
        assert_eq!(reg.name, "info-test");
        assert_eq!(reg.target_seams, vec!["AA01-SEAM-SCHED-CANCEL-STREAK"]);
    }

    #[test]
    fn controller_ids_listed() {
        let mut registry = ControllerRegistry::new();
        let id1 = registry.register(test_registration("a")).unwrap();
        let id2 = registry.register(test_registration("b")).unwrap();
        let ids = registry.controller_ids();
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn log_sink_receives_registration_event() {
        use parking_lot::Mutex;
        let logs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let logs_clone = Arc::clone(&logs);
        let mut registry = ControllerRegistry::new().with_log_sink(Arc::new(move |msg: &str| {
            logs_clone.lock().push(msg.to_string());
        }));
        registry.register(test_registration("logged")).unwrap();
        {
            let captured = logs.lock();
            assert_eq!(captured.len(), 1);
            assert!(captured[0].contains("controller_registered"));
            assert!(captured[0].contains("logged"));
            drop(captured);
        }
    }

    #[test]
    fn decision_for_unknown_controller_returns_false() {
        let mut registry = ControllerRegistry::new();
        let decision = ControllerDecision {
            controller_id: ControllerId(999),
            snapshot_id: SnapshotId(1),
            label: "ghost".to_string(),
            payload: serde_json::Value::Null,
            confidence: 1.0,
            fallback_label: "noop".to_string(),
        };
        assert!(!registry.record_decision(&decision));
    }

    #[test]
    fn version_display() {
        let v = SnapshotVersion { major: 1, minor: 2 };
        assert_eq!(format!("{v}"), "1.2");
    }

    #[test]
    fn error_display_coverage() {
        let errors = [
            RegistrationError::EmptyName,
            RegistrationError::InvertedVersionRange,
            RegistrationError::IncompatibleVersion {
                current: SnapshotVersion { major: 1, minor: 0 },
                min: SnapshotVersion { major: 2, minor: 0 },
                max: SnapshotVersion { major: 2, minor: 0 },
            },
            RegistrationError::UnsupportedFields(vec!["foo".to_string()]),
            RegistrationError::NoTargetSeams,
            RegistrationError::ZeroBudget,
            RegistrationError::DuplicateName("dup".to_string()),
        ];
        for error in &errors {
            let msg = format!("{error}");
            assert!(!msg.is_empty());
        }
    }

    // ── AA-02.3: Shadow, canary, rollback, evidence-ledger validation ──

    fn registry_with_policy(policy: PromotionPolicy) -> ControllerRegistry {
        let mut r = ControllerRegistry::new();
        r.set_promotion_policy(policy);
        r
    }

    fn fast_policy() -> PromotionPolicy {
        PromotionPolicy {
            min_calibration_score: 0.8,
            min_shadow_epochs: 2,
            min_canary_epochs: 1,
            max_budget_overruns: 3,
            policy_id: "test-fast-v1".to_string(),
        }
    }

    #[test]
    fn promote_shadow_to_canary() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("promo")).unwrap();
        registry.update_calibration(id, 0.9);
        // Need 2 epochs in shadow
        registry.advance_epoch();
        registry.advance_epoch();
        let result = registry.try_promote(id, ControllerMode::Canary);
        assert_eq!(result, Ok(ControllerMode::Canary));
        assert_eq!(registry.mode(id), Some(ControllerMode::Canary));
        assert_eq!(registry.epochs_in_current_mode(id), Some(0));
    }

    #[test]
    fn promote_canary_to_active() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("canary-up")).unwrap();
        registry.update_calibration(id, 0.95);
        registry.advance_epoch();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Canary).unwrap();
        registry.advance_epoch();
        let result = registry.try_promote(id, ControllerMode::Active);
        assert_eq!(result, Ok(ControllerMode::Active));
    }

    #[test]
    fn promote_rejects_insufficient_epochs() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("too-soon")).unwrap();
        registry.update_calibration(id, 0.9);
        // Only 1 epoch, need 2
        registry.advance_epoch();
        let result = registry.try_promote(id, ControllerMode::Canary);
        assert!(matches!(
            result,
            Err(PromotionRejection::InsufficientEpochs {
                current: 1,
                required: 2,
                ..
            })
        ));
    }

    #[test]
    fn promote_rejects_low_calibration() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("low-cal")).unwrap();
        registry.update_calibration(id, 0.5);
        registry.advance_epoch();
        registry.advance_epoch();
        let result = registry.try_promote(id, ControllerMode::Canary);
        assert!(matches!(
            result,
            Err(PromotionRejection::CalibrationTooLow { .. })
        ));
    }

    #[test]
    fn promote_rejects_invalid_transition_shadow_to_active() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("skip")).unwrap();
        registry.update_calibration(id, 0.99);
        registry.advance_epoch();
        registry.advance_epoch();
        registry.advance_epoch();
        let result = registry.try_promote(id, ControllerMode::Active);
        assert!(matches!(
            result,
            Err(PromotionRejection::InvalidTransition { .. })
        ));
    }

    #[test]
    fn promote_rejects_active_to_canary() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("backward")).unwrap();
        registry.update_calibration(id, 0.95);
        registry.advance_epoch();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Canary).unwrap();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Active).unwrap();
        let result = registry.try_promote(id, ControllerMode::Canary);
        assert!(matches!(
            result,
            Err(PromotionRejection::InvalidTransition { .. })
        ));
    }

    #[test]
    fn rollback_from_active_to_shadow() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("rollme")).unwrap();
        registry.update_calibration(id, 0.95);
        registry.advance_epoch();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Canary).unwrap();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Active).unwrap();

        let cmd = registry
            .rollback(id, RollbackReason::CalibrationRegression { score: 0.3 })
            .unwrap();
        assert_eq!(registry.mode(id), Some(ControllerMode::Shadow));
        assert_eq!(cmd.rolled_back_from, ControllerMode::Active);
        assert_eq!(cmd.rolled_back_to, ControllerMode::Shadow);
        assert_eq!(cmd.controller_name, "rollme");
        assert!(!cmd.remediation.is_empty());
        assert!(registry.is_fallback_active(id));
    }

    #[test]
    fn rollback_from_canary_to_shadow() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("can-roll")).unwrap();
        registry.update_calibration(id, 0.9);
        registry.advance_epoch();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Canary).unwrap();

        let cmd = registry
            .rollback(id, RollbackReason::ManualRollback)
            .unwrap();
        assert_eq!(cmd.rolled_back_from, ControllerMode::Canary);
        assert_eq!(cmd.rolled_back_to, ControllerMode::Shadow);
    }

    #[test]
    fn rollback_from_shadow_returns_none() {
        let mut registry = ControllerRegistry::new();
        let id = registry
            .register(test_registration("already-shadow"))
            .unwrap();
        assert!(
            registry
                .rollback(id, RollbackReason::ManualRollback)
                .is_none()
        );
    }

    #[test]
    fn hold_and_release() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("holdme")).unwrap();
        registry.update_calibration(id, 0.9);
        registry.advance_epoch();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Canary).unwrap();

        assert!(registry.hold(id));
        assert_eq!(registry.mode(id), Some(ControllerMode::Hold));

        // Cannot promote while held
        let result = registry.try_promote(id, ControllerMode::Active);
        assert!(matches!(
            result,
            Err(PromotionRejection::HeldForInvestigation)
        ));

        // Release restores previous mode
        let restored = registry.release_hold(id).unwrap();
        assert_eq!(restored, ControllerMode::Canary);
        assert_eq!(registry.mode(id), Some(ControllerMode::Canary));
    }

    #[test]
    fn hold_already_held_returns_false() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("double-hold")).unwrap();
        assert!(registry.hold(id));
        assert!(!registry.hold(id));
    }

    #[test]
    fn release_non_held_returns_none() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("not-held")).unwrap();
        assert!(registry.release_hold(id).is_none());
    }

    #[test]
    fn fallback_lifecycle() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("fb")).unwrap();
        assert!(!registry.is_fallback_active(id));
        registry.update_calibration(id, 0.9);
        registry.advance_epoch();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Canary).unwrap();
        registry.rollback(
            id,
            RollbackReason::FallbackTriggered {
                decision_label: "bad-decision".to_string(),
            },
        );
        assert!(registry.is_fallback_active(id));
        registry.clear_fallback(id);
        assert!(!registry.is_fallback_active(id));
    }

    #[test]
    fn evidence_ledger_records_registration() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("ledger-reg")).unwrap();
        let entries = registry.controller_ledger(id);
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0].event, LedgerEvent::Registered { .. }));
    }

    #[test]
    fn evidence_ledger_records_full_lifecycle() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("full-life")).unwrap();
        registry.update_calibration(id, 0.95);
        registry.advance_epoch();
        registry.advance_epoch();

        // Promote to canary
        registry.try_promote(id, ControllerMode::Canary).unwrap();
        registry.advance_epoch();

        // Promote to active
        registry.try_promote(id, ControllerMode::Active).unwrap();

        // Rollback
        registry.rollback(id, RollbackReason::ManualRollback);

        let entries = registry.controller_ledger(id);
        // Registered + 2 Promoted + RolledBack = 4
        assert_eq!(entries.len(), 4);
        assert!(matches!(entries[0].event, LedgerEvent::Registered { .. }));
        assert!(matches!(
            entries[1].event,
            LedgerEvent::Promoted {
                from: ControllerMode::Shadow,
                to: ControllerMode::Canary,
                ..
            }
        ));
        assert!(matches!(
            entries[2].event,
            LedgerEvent::Promoted {
                from: ControllerMode::Canary,
                to: ControllerMode::Active,
                ..
            }
        ));
        assert!(matches!(
            entries[3].event,
            LedgerEvent::RolledBack {
                from: ControllerMode::Active,
                to: ControllerMode::Shadow,
                ..
            }
        ));
    }

    #[test]
    fn evidence_ledger_records_decisions() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("dec-ledger")).unwrap();
        let snap_id = registry.next_snapshot_id();
        let decision = ControllerDecision {
            controller_id: id,
            snapshot_id: snap_id,
            label: "adjust-streak".to_string(),
            payload: serde_json::Value::Null,
            confidence: 0.9,
            fallback_label: "noop".to_string(),
        };
        registry.record_decision(&decision);
        let entries = registry.controller_ledger(id);
        // Registered + DecisionRecorded
        assert_eq!(entries.len(), 2);
        assert!(matches!(
            &entries[1].event,
            LedgerEvent::DecisionRecorded {
                label,
                confidence,
                fallback_label,
                within_budget: true,
            } if label == "adjust-streak" && (*confidence - 0.9).abs() < f64::EPSILON && fallback_label == "noop"
        ));
    }

    #[test]
    fn evidence_ledger_records_decision_metadata() {
        let mut registry = ControllerRegistry::new();
        let id = registry
            .register(test_registration("decision-metadata"))
            .unwrap();
        let snap_id = registry.next_snapshot_id();
        let decision = ControllerDecision {
            controller_id: id,
            snapshot_id: snap_id,
            label: "retune-queue".to_string(),
            payload: serde_json::json!({ "limit": 8 }),
            confidence: 0.42,
            fallback_label: "shadow-default".to_string(),
        };

        assert!(registry.record_decision(&decision));

        let entries = registry.controller_ledger(id);
        let event = &entries[1].event;
        match event {
            LedgerEvent::DecisionRecorded {
                label,
                confidence,
                fallback_label,
                within_budget,
            } => {
                assert_eq!(label, "retune-queue");
                assert!((*confidence - 0.42).abs() < f64::EPSILON);
                assert_eq!(fallback_label, "shadow-default");
                assert!(*within_budget);
            }
            other => panic!("unexpected ledger event: {other:?}"),
        }
    }

    #[test]
    fn stale_decision_does_not_regress_last_snapshot_watermark() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry
            .register(test_registration("stale-snapshot"))
            .unwrap();
        registry.update_calibration(id, 0.95);
        registry.advance_epoch();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Canary).unwrap();

        let first = registry.next_snapshot_id();
        let second = registry.next_snapshot_id();
        let newer = ControllerDecision {
            controller_id: id,
            snapshot_id: second,
            label: "newer".to_string(),
            payload: serde_json::Value::Null,
            confidence: 0.9,
            fallback_label: "noop".to_string(),
        };
        let stale = ControllerDecision {
            controller_id: id,
            snapshot_id: first,
            label: "stale".to_string(),
            payload: serde_json::Value::Null,
            confidence: 0.9,
            fallback_label: "noop".to_string(),
        };

        assert!(registry.record_decision(&newer));
        assert!(!registry.record_decision(&stale));

        let rollback = registry
            .rollback(id, RollbackReason::ManualRollback)
            .expect("canary controller should roll back");
        assert_eq!(rollback.at_snapshot_id, Some(second));
    }

    #[test]
    fn evidence_ledger_records_promotion_rejections() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry
            .register(test_registration("reject-ledger"))
            .unwrap();
        registry.update_calibration(id, 0.5);
        registry.advance_epoch();
        registry.advance_epoch();
        let _ = registry.try_promote(id, ControllerMode::Canary);
        let entries = registry.controller_ledger(id);
        // Registered + PromotionRejected
        assert_eq!(entries.len(), 2);
        assert!(matches!(
            entries[1].event,
            LedgerEvent::PromotionRejected { .. }
        ));
    }

    #[test]
    fn evidence_ledger_records_hold_and_release() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("hold-ledger")).unwrap();
        registry.hold(id);
        registry.release_hold(id);
        let entries = registry.controller_ledger(id);
        // Registered + Held + Released
        assert_eq!(entries.len(), 3);
        assert!(matches!(entries[1].event, LedgerEvent::Held { .. }));
        assert!(matches!(entries[2].event, LedgerEvent::Released { .. }));
    }

    #[test]
    fn evidence_ledger_records_deregistration() {
        let mut registry = ControllerRegistry::new();
        let id = registry
            .register(test_registration("dereg-ledger"))
            .unwrap();
        registry.deregister(id);
        let entries = registry.controller_ledger(id);
        // Registered + Deregistered
        assert_eq!(entries.len(), 2);
        assert!(matches!(entries[1].event, LedgerEvent::Deregistered));
    }

    #[test]
    fn ledger_entry_ids_are_monotonic() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("mono")).unwrap();
        registry.hold(id);
        registry.release_hold(id);
        let ledger = registry.evidence_ledger();
        for pair in ledger.windows(2) {
            assert!(pair[0].entry_id < pair[1].entry_id);
        }
    }

    #[test]
    fn ledger_entries_carry_policy_id() {
        let policy = fast_policy();
        let expected_id = policy.policy_id.clone();
        let mut registry = registry_with_policy(policy);
        let id = registry
            .register(test_registration("policy-trace"))
            .unwrap();
        registry.hold(id);
        for entry in registry.controller_ledger(id) {
            assert_eq!(entry.policy_id, expected_id);
        }
    }

    #[test]
    fn budget_overruns_tracked() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("overruns")).unwrap();
        let snap_id = registry.next_snapshot_id();
        let decision = ControllerDecision {
            controller_id: id,
            snapshot_id: snap_id,
            label: "test".to_string(),
            payload: serde_json::Value::Null,
            confidence: 0.9,
            fallback_label: "noop".to_string(),
        };
        // 1st within budget, 2nd exceeds (budget=1)
        registry.record_decision(&decision);
        registry.record_decision(&decision);
        registry.record_decision(&decision);
        assert_eq!(registry.budget_overruns(id), Some(2));
    }

    #[test]
    fn decision_counters_saturate_without_wrapping() {
        let mut registry = ControllerRegistry::new();
        let id = registry
            .register(test_registration("saturating-counters"))
            .unwrap();
        let snap_id = registry.next_snapshot_id();
        let decision = ControllerDecision {
            controller_id: id,
            snapshot_id: snap_id,
            label: "spam".to_string(),
            payload: serde_json::Value::Null,
            confidence: 0.9,
            fallback_label: "noop".to_string(),
        };

        let controller = registry
            .controllers
            .get_mut(&id)
            .expect("controller must exist");
        controller.registration.budget.max_decisions_per_epoch = u32::MAX;
        controller.decisions_this_epoch = u32::MAX;
        controller.budget_overruns = u32::MAX;

        assert!(
            !registry.record_decision(&decision),
            "a saturated decision counter must stay over-budget instead of wrapping back in-budget"
        );
        let controller = registry
            .controllers
            .get(&id)
            .expect("controller must exist");
        assert_eq!(controller.decisions_this_epoch, u32::MAX);
        assert_eq!(controller.budget_overruns, u32::MAX);
    }

    #[test]
    fn advance_epoch_increments_mode_counter() {
        let mut registry = ControllerRegistry::new();
        let id = registry.register(test_registration("epoch-count")).unwrap();
        assert_eq!(registry.epochs_in_current_mode(id), Some(0));
        registry.advance_epoch();
        assert_eq!(registry.epochs_in_current_mode(id), Some(1));
        registry.advance_epoch();
        assert_eq!(registry.epochs_in_current_mode(id), Some(2));
    }

    #[test]
    fn recovery_command_has_remediation() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("recovery")).unwrap();
        registry.update_calibration(id, 0.95);
        registry.advance_epoch();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Canary).unwrap();

        let cmd = registry
            .rollback(id, RollbackReason::BudgetOverruns { count: 5 })
            .unwrap();
        assert_eq!(cmd.policy_id, "test-fast-v1");
        assert!(!cmd.remediation.is_empty());
        assert!(cmd.remediation.iter().any(|r| r.contains("budget")));
    }

    #[test]
    fn recovery_command_for_fallback_triggered() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry
            .register(test_registration("fallback-cmd"))
            .unwrap();
        registry.update_calibration(id, 0.9);
        registry.advance_epoch();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Canary).unwrap();

        let cmd = registry
            .rollback(
                id,
                RollbackReason::FallbackTriggered {
                    decision_label: "bad-action".to_string(),
                },
            )
            .unwrap();
        assert!(cmd.remediation.iter().any(|r| r.contains("bad-action")));
    }

    #[test]
    fn structured_log_covers_promotion_and_rollback() {
        use parking_lot::Mutex;
        let logs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let logs_clone = Arc::clone(&logs);
        let mut registry = registry_with_policy(fast_policy());
        registry = registry.with_log_sink(Arc::new(move |msg: &str| {
            logs_clone.lock().push(msg.to_string());
        }));
        let id = registry.register(test_registration("log-promo")).unwrap();
        registry.update_calibration(id, 0.9);
        registry.advance_epoch();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Canary).unwrap();
        registry.rollback(id, RollbackReason::ManualRollback);

        {
            let captured = logs.lock();
            assert!(captured.iter().any(|l| l.contains("controller_promoted")));
            assert!(
                captured
                    .iter()
                    .any(|l| l.contains("controller_rolled_back"))
            );
            assert!(
                captured
                    .iter()
                    .any(|l| l.contains("policy_id=test-fast-v1"))
            );
            drop(captured);
        }
    }

    #[test]
    fn structured_log_covers_promotion_rejection() {
        use parking_lot::Mutex;
        let logs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let logs_clone = Arc::clone(&logs);
        let mut registry = registry_with_policy(fast_policy());
        registry = registry.with_log_sink(Arc::new(move |msg: &str| {
            logs_clone.lock().push(msg.to_string());
        }));
        let id = registry.register(test_registration("log-reject")).unwrap();
        registry.update_calibration(id, 0.5);
        registry.advance_epoch();
        registry.advance_epoch();
        let _ = registry.try_promote(id, ControllerMode::Canary);

        {
            let captured = logs.lock();
            assert!(
                captured
                    .iter()
                    .any(|l| l.contains("controller_promotion_rejected"))
            );
            drop(captured);
        }
    }

    #[test]
    fn structured_log_covers_hold_and_release() {
        use parking_lot::Mutex;
        let logs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let logs_clone = Arc::clone(&logs);
        let mut registry = ControllerRegistry::new();
        registry = registry.with_log_sink(Arc::new(move |msg: &str| {
            logs_clone.lock().push(msg.to_string());
        }));
        let id = registry.register(test_registration("log-hold")).unwrap();
        registry.hold(id);
        registry.release_hold(id);

        {
            let captured = logs.lock();
            assert!(captured.iter().any(|l| l.contains("controller_held")));
            assert!(captured.iter().any(|l| l.contains("controller_released")));
            drop(captured);
        }
    }

    #[test]
    fn promotion_rejection_display_coverage() {
        let rejections = [
            PromotionRejection::ControllerNotFound,
            PromotionRejection::CalibrationTooLow {
                current: 0.5,
                required: 0.8,
            },
            PromotionRejection::InsufficientEpochs {
                current: 1,
                required: 3,
                mode: ControllerMode::Shadow,
            },
            PromotionRejection::InvalidTransition {
                from: ControllerMode::Shadow,
                to: ControllerMode::Active,
            },
            PromotionRejection::HeldForInvestigation,
        ];
        for rejection in &rejections {
            let msg = format!("{rejection}");
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn rollback_reason_display_coverage() {
        let reasons = [
            RollbackReason::CalibrationRegression { score: 0.3 },
            RollbackReason::BudgetOverruns { count: 5 },
            RollbackReason::ManualRollback,
            RollbackReason::FallbackTriggered {
                decision_label: "test".to_string(),
            },
        ];
        for reason in &reasons {
            let msg = format!("{reason}");
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn e2e_promotion_cannot_bypass_verification() {
        // Scenario: a controller tries to skip the pipeline
        let mut registry = registry_with_policy(fast_policy());
        let id = registry
            .register(test_registration("bypass-attempt"))
            .unwrap();

        // Attempt 1: promote directly to Active from Shadow (must fail)
        registry.update_calibration(id, 0.99);
        for _ in 0..10 {
            registry.advance_epoch();
        }
        assert!(matches!(
            registry.try_promote(id, ControllerMode::Active),
            Err(PromotionRejection::InvalidTransition { .. })
        ));

        // Attempt 2: promote to Canary without sufficient calibration
        registry.update_calibration(id, 0.1);
        assert!(matches!(
            registry.try_promote(id, ControllerMode::Canary),
            Err(PromotionRejection::CalibrationTooLow { .. })
        ));

        // Attempt 3: re-asserting Shadow starts a fresh residency window, so
        // the controller still cannot bypass the minimum shadow epochs.
        registry.update_calibration(id, 0.99);
        registry.set_mode(id, ControllerMode::Shadow);
        assert!(matches!(
            registry.try_promote(id, ControllerMode::Canary),
            Err(PromotionRejection::InsufficientEpochs {
                current: 0,
                required: 2,
                ..
            })
        ));
        registry.advance_epoch();
        assert!(matches!(
            registry.try_promote(id, ControllerMode::Canary),
            Err(PromotionRejection::InsufficientEpochs {
                current: 1,
                required: 2,
                ..
            })
        ));
        registry.advance_epoch();
        assert!(registry.try_promote(id, ControllerMode::Canary).is_ok());

        // Correct path: full pipeline
        let id2 = registry
            .register(test_registration("correct-path"))
            .unwrap();
        registry.update_calibration(id2, 0.9);
        assert!(registry.try_promote(id2, ControllerMode::Canary).is_err()); // 0 epochs
        registry.advance_epoch();
        assert!(registry.try_promote(id2, ControllerMode::Canary).is_err()); // 1 epoch
        registry.advance_epoch();
        assert!(registry.try_promote(id2, ControllerMode::Canary).is_ok()); // 2 epochs
        assert!(registry.try_promote(id2, ControllerMode::Active).is_err()); // 0 canary epochs
        registry.advance_epoch();
        assert!(registry.try_promote(id2, ControllerMode::Active).is_ok()); // 1 canary epoch
        assert_eq!(registry.mode(id2), Some(ControllerMode::Active));
    }

    #[test]
    fn e2e_failed_rollout_leaves_conservative_state() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry
            .register(test_registration("failed-rollout"))
            .unwrap();
        registry.update_calibration(id, 0.9);
        registry.advance_epoch();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Canary).unwrap();
        registry.advance_epoch();
        registry.try_promote(id, ControllerMode::Active).unwrap();

        // Simulate calibration regression triggering rollback
        registry.update_calibration(id, 0.2);
        let cmd = registry
            .rollback(id, RollbackReason::CalibrationRegression { score: 0.2 })
            .unwrap();

        // Verify conservative state
        assert_eq!(registry.mode(id), Some(ControllerMode::Shadow));
        assert!(registry.is_fallback_active(id));
        assert_eq!(cmd.rolled_back_to, ControllerMode::Shadow);
        assert!(!cmd.remediation.is_empty());

        // Cannot re-promote without clearing conditions
        assert!(registry.try_promote(id, ControllerMode::Canary).is_err());
    }

    #[test]
    fn e2e_hold_blocks_entire_pipeline() {
        let mut registry = registry_with_policy(fast_policy());
        let id = registry.register(test_registration("hold-block")).unwrap();
        registry.update_calibration(id, 0.99);
        registry.advance_epoch();
        registry.advance_epoch();

        registry.hold(id);
        // All promotion attempts fail while held
        assert!(matches!(
            registry.try_promote(id, ControllerMode::Canary),
            Err(PromotionRejection::HeldForInvestigation)
        ));

        // Release and verify pipeline resumes
        registry.release_hold(id);
        // Epochs reset on release, need to accumulate again
        registry.advance_epoch();
        registry.advance_epoch();
        assert!(registry.try_promote(id, ControllerMode::Canary).is_ok());
    }

    #[test]
    fn recovery_command_serializable() {
        let cmd = RecoveryCommand {
            controller_id: ControllerId(42),
            controller_name: "test-ctrl".to_string(),
            rolled_back_from: ControllerMode::Active,
            rolled_back_to: ControllerMode::Shadow,
            reason: RollbackReason::ManualRollback,
            policy_id: "test-v1".to_string(),
            at_snapshot_id: Some(SnapshotId(100)),
            remediation: vec!["check logs".to_string()],
        };
        let json = serde_json::to_string(&cmd).unwrap();
        let deser: RecoveryCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.controller_id, ControllerId(42));
        assert_eq!(deser.controller_name, "test-ctrl");
    }

    #[test]
    fn evidence_ledger_entry_serializable() {
        let entry = EvidenceLedgerEntry {
            entry_id: 1,
            controller_id: ControllerId(1),
            snapshot_id: Some(SnapshotId(5)),
            event: LedgerEvent::Promoted {
                from: ControllerMode::Shadow,
                to: ControllerMode::Canary,
                calibration_score: 0.85,
            },
            policy_id: "test".to_string(),
            timestamp: Time::ZERO,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let deser: EvidenceLedgerEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.entry_id, 1);
    }

    #[test]
    fn default_promotion_policy_values() {
        let policy = PromotionPolicy::default();
        assert!((policy.min_calibration_score - 0.8).abs() < f64::EPSILON);
        assert_eq!(policy.min_shadow_epochs, 3);
        assert_eq!(policy.min_canary_epochs, 2);
        assert_eq!(policy.max_budget_overruns, 3);
        assert_eq!(policy.policy_id, "default-promotion-policy-v1");
    }
