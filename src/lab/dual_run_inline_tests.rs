    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    // --- SeedMode ---

    #[test]
    fn seed_mode_serde_roundtrip() {
        init_test("seed_mode_serde_roundtrip");
        let json = serde_json::to_string(&SeedMode::Inherit).unwrap();
        assert_eq!(json, "\"inherit\"");
        let parsed: SeedMode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, SeedMode::Inherit);

        let json = serde_json::to_string(&SeedMode::Override).unwrap();
        assert_eq!(json, "\"override\"");
        let parsed: SeedMode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, SeedMode::Override);
        crate::test_complete!("seed_mode_serde_roundtrip");
    }

    // --- ReplayPolicy ---

    #[test]
    fn replay_policy_serde_roundtrip() {
        init_test("replay_policy_serde_roundtrip");
        for policy in [
            ReplayPolicy::SingleSeed,
            ReplayPolicy::SeedSweep,
            ReplayPolicy::ReplayBundle,
        ] {
            let json = serde_json::to_string(&policy).unwrap();
            let parsed: ReplayPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, policy);
        }
        crate::test_complete!("replay_policy_serde_roundtrip");
    }

    // --- SeedPlan ---

    #[test]
    fn seed_plan_inherit_uses_canonical() {
        init_test("seed_plan_inherit_uses_canonical");
        let plan = SeedPlan::inherit(0xBEEF, "test-scenario");
        assert_eq!(plan.effective_lab_seed(), 0xBEEF);
        assert_eq!(plan.effective_live_seed(), 0xBEEF);
        assert_eq!(plan.lab_seed_mode, SeedMode::Inherit);
        assert_eq!(plan.live_seed_mode, SeedMode::Inherit);
        crate::test_complete!("seed_plan_inherit_uses_canonical");
    }

    #[test]
    fn seed_plan_override_uses_explicit_seed() {
        init_test("seed_plan_override_uses_explicit_seed");
        let plan = SeedPlan::inherit(0xBEEF, "test")
            .with_lab_override(0xCAFE)
            .with_live_override(0xFACE);
        assert_eq!(plan.effective_lab_seed(), 0xCAFE);
        assert_eq!(plan.effective_live_seed(), 0xFACE);
        assert_eq!(plan.lab_seed_mode, SeedMode::Override);
        assert_eq!(plan.live_seed_mode, SeedMode::Override);
        crate::test_complete!("seed_plan_override_uses_explicit_seed");
    }

    #[test]
    fn seed_plan_override_without_value_falls_back_to_canonical() {
        init_test("seed_plan_override_without_value_falls_back");
        let mut plan = SeedPlan::inherit(0xBEEF, "test");
        plan.lab_seed_mode = SeedMode::Override;
        // No lab_seed_override set — should fall back to canonical.
        assert_eq!(plan.effective_lab_seed(), 0xBEEF);
        crate::test_complete!("seed_plan_override_without_value_falls_back");
    }

    #[test]
    fn seed_plan_entropy_derives_from_effective() {
        init_test("seed_plan_entropy_derives_from_effective");
        let plan = SeedPlan::inherit(42, "test");
        let entropy = plan.effective_entropy_seed(42);
        // Must be deterministic.
        assert_eq!(entropy, plan.effective_entropy_seed(42));
        // Must differ from the seed itself (extremely unlikely to collide).
        assert_ne!(entropy, 42);
        crate::test_complete!("seed_plan_entropy_derives_from_effective");
    }

    #[test]
    fn seed_plan_entropy_override() {
        init_test("seed_plan_entropy_override");
        let plan = SeedPlan::inherit(42, "test").with_entropy_seed(999);
        assert_eq!(plan.effective_entropy_seed(42), 999);
        assert_eq!(plan.effective_entropy_seed(100), 999);
        crate::test_complete!("seed_plan_entropy_override");
    }

    #[test]
    fn seed_plan_to_lab_config() {
        init_test("seed_plan_to_lab_config");
        let plan = SeedPlan::inherit(0xDEAD, "test");
        let config = plan.to_lab_config();
        assert_eq!(config.seed, 0xDEAD);
        let expected_entropy = plan.effective_entropy_seed(0xDEAD);
        assert_eq!(config.entropy_seed, expected_entropy);
        crate::test_complete!("seed_plan_to_lab_config");
    }

    #[test]
    fn seed_plan_to_lab_config_with_override() {
        init_test("seed_plan_to_lab_config_with_override");
        let plan = SeedPlan::inherit(0xDEAD, "test").with_lab_override(0xCAFE);
        let config = plan.to_lab_config();
        assert_eq!(config.seed, 0xCAFE);
        crate::test_complete!("seed_plan_to_lab_config_with_override");
    }

    #[test]
    fn seed_plan_sweep_deterministic() {
        init_test("seed_plan_sweep_deterministic");
        let plan = SeedPlan::inherit(42, "test").with_replay_policy(ReplayPolicy::SeedSweep);
        let seeds1 = plan.sweep_seeds(5);
        let seeds2 = plan.sweep_seeds(5);
        assert_eq!(seeds1, seeds2);
        assert_eq!(seeds1.len(), 5);
        // All seeds should be distinct.
        let mut unique = seeds1;
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), 5);
        crate::test_complete!("seed_plan_sweep_deterministic");
    }

    #[test]
    fn seed_plan_serde_roundtrip() {
        init_test("seed_plan_serde_roundtrip");
        let plan = SeedPlan::inherit(0xABCD, "lineage-1")
            .with_lab_override(0x1234)
            .with_entropy_seed(0x5678)
            .with_replay_policy(ReplayPolicy::SeedSweep);
        let json = serde_json::to_string_pretty(&plan).unwrap();
        let parsed: SeedPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, plan);
        crate::test_complete!("seed_plan_serde_roundtrip");
    }

    #[test]
    fn seed_plan_display() {
        init_test("seed_plan_display");
        let plan = SeedPlan::inherit(42, "test-scenario");
        let display = format!("{plan}");
        assert!(display.contains("0x2A"));
        assert!(display.contains("test-scenario"));
        crate::test_complete!("seed_plan_display");
    }

    // --- ScenarioFamilyId ---

    #[test]
    fn scenario_family_id_display() {
        init_test("scenario_family_id_display");
        let fam = ScenarioFamilyId::new("cancel.race", "cancellation.race", "v1");
        let s = format!("{fam}");
        assert!(s.contains("cancel.race"));
        assert!(s.contains("cancellation.race"));
        assert!(s.contains("v1"));
        crate::test_complete!("scenario_family_id_display");
    }

    #[test]
    fn scenario_family_id_serde_roundtrip() {
        init_test("scenario_family_id_serde_roundtrip");
        let fam = ScenarioFamilyId::new("cancel.race", "cancellation.race", "v1");
        let json = serde_json::to_string(&fam).unwrap();
        let parsed: ScenarioFamilyId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, fam);
        crate::test_complete!("scenario_family_id_serde_roundtrip");
    }

    // --- ExecutionInstanceId ---

    #[test]
    fn execution_instance_lab_vs_live() {
        init_test("execution_instance_lab_vs_live");
        let lab = ExecutionInstanceId::lab("test-family", 42);
        let live = ExecutionInstanceId::live("test-family", 42);
        assert_eq!(lab.runtime_kind, RuntimeKind::Lab);
        assert_eq!(live.runtime_kind, RuntimeKind::Live);
        assert_ne!(lab.key(), live.key());
        crate::test_complete!("execution_instance_lab_vs_live");
    }

    #[test]
    fn execution_instance_key_stable() {
        init_test("execution_instance_key_stable");
        let inst = ExecutionInstanceId::lab("fam", 0xBEEF).with_run_index(3);
        let key1 = inst.key();
        let key2 = inst.key();
        assert_eq!(key1, key2);
        assert!(key1.contains("fam"));
        assert!(key1.contains("0xBEEF"));
        assert!(key1.contains('3'));
        crate::test_complete!("execution_instance_key_stable");
    }

    // --- RuntimeKind ---

    #[test]
    fn runtime_kind_display() {
        init_test("runtime_kind_display");
        assert_eq!(format!("{}", RuntimeKind::Lab), "lab");
        assert_eq!(format!("{}", RuntimeKind::Live), "live");
        crate::test_complete!("runtime_kind_display");
    }

    // --- ReplayMetadata ---

    #[test]
    fn replay_metadata_lab_seeds_match_plan() {
        init_test("replay_metadata_lab_seeds_match_plan");
        let family = ScenarioFamilyId::new("test", "surface", "v1");
        let plan = SeedPlan::inherit(0xDEAD, "lineage");
        let meta = ReplayMetadata::for_lab(family, &plan);
        assert_eq!(meta.effective_seed, 0xDEAD);
        assert_eq!(meta.instance.runtime_kind, RuntimeKind::Lab);
        assert_eq!(
            meta.effective_entropy_seed,
            plan.effective_entropy_seed(0xDEAD)
        );
        crate::test_complete!("replay_metadata_lab_seeds_match_plan");
    }

    #[test]
    fn replay_metadata_live_seeds_match_plan() {
        init_test("replay_metadata_live_seeds_match_plan");
        let family = ScenarioFamilyId::new("test", "surface", "v1");
        let plan = SeedPlan::inherit(0xCAFE, "lineage");
        let meta = ReplayMetadata::for_live(family, &plan);
        assert_eq!(meta.effective_seed, 0xCAFE);
        assert_eq!(meta.instance.runtime_kind, RuntimeKind::Live);
        crate::test_complete!("replay_metadata_live_seeds_match_plan");
    }

    #[test]
    fn replay_metadata_with_overrides() {
        init_test("replay_metadata_with_overrides");
        let family = ScenarioFamilyId::new("test", "surface", "v1");
        let plan = SeedPlan::inherit(42, "lineage").with_lab_override(999);
        let meta = ReplayMetadata::for_lab(family, &plan);
        assert_eq!(meta.effective_seed, 999);
        crate::test_complete!("replay_metadata_with_overrides");
    }

    #[test]
    fn replay_metadata_with_lab_report() {
        init_test("replay_metadata_with_lab_report");
        let family = ScenarioFamilyId::new("test", "surface", "v1");
        let plan = SeedPlan::inherit(42, "lineage");
        let meta = ReplayMetadata::for_lab(family, &plan)
            .with_lab_report(0xF1, 0xE1, 100, 0x51, 500)
            .with_repro_command("cargo test test -- --nocapture")
            .with_artifact_path("/tmp/artifacts/test");
        assert_eq!(meta.trace_fingerprint, Some(0xF1));
        assert_eq!(meta.event_count, Some(100));
        assert_eq!(meta.steps_total, Some(500));
        assert!(meta.repro_command.is_some());
        assert!(meta.artifact_path.is_some());
        crate::test_complete!("replay_metadata_with_lab_report");
    }

    #[test]
    fn replay_metadata_default_repro_command() {
        init_test("replay_metadata_default_repro_command");
        let family = ScenarioFamilyId::new("cancel.race", "surface", "v1");
        let plan = SeedPlan::inherit(0xDEAD, "lineage");
        let meta = ReplayMetadata::for_lab(family, &plan);
        let cmd = meta.default_repro_command();
        assert!(cmd.contains("rch exec -- env ASUPERSYNC_SEED=0xDEAD"));
        assert!(cmd.contains("0xDEAD"));
        assert!(cmd.contains("cancel.race"));
        crate::test_complete!("replay_metadata_default_repro_command");
    }

    #[test]
    fn replay_metadata_serde_roundtrip() {
        init_test("replay_metadata_serde_roundtrip");
        let family = ScenarioFamilyId::new("test", "surface", "v1");
        let plan = SeedPlan::inherit(42, "lineage");
        let meta = ReplayMetadata::for_lab(family, &plan).with_repro_command("cargo test");
        let json = serde_json::to_string_pretty(&meta).unwrap();
        let parsed: ReplayMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.effective_seed, meta.effective_seed);
        assert_eq!(parsed.family.id, "test");
        crate::test_complete!("replay_metadata_serde_roundtrip");
    }

    // --- SeedLineageRecord ---

    #[test]
    fn seed_lineage_record_inherit_seeds_match() {
        init_test("seed_lineage_record_inherit_seeds_match");
        let plan = SeedPlan::inherit(0xBEEF, "lineage-1");
        let record = SeedLineageRecord::from_plan(&plan);
        assert!(record.seeds_match);
        assert_eq!(record.lab_effective_seed, 0xBEEF);
        assert_eq!(record.live_effective_seed, 0xBEEF);
        assert_eq!(record.lab_entropy_seed, record.live_entropy_seed);
        crate::test_complete!("seed_lineage_record_inherit_seeds_match");
    }

    #[test]
    fn seed_lineage_record_override_seeds_differ() {
        init_test("seed_lineage_record_override_seeds_differ");
        let plan = SeedPlan::inherit(42, "lineage-1")
            .with_lab_override(100)
            .with_live_override(200);
        let record = SeedLineageRecord::from_plan(&plan);
        assert!(!record.seeds_match);
        assert_eq!(record.lab_effective_seed, 100);
        assert_eq!(record.live_effective_seed, 200);
        crate::test_complete!("seed_lineage_record_override_seeds_differ");
    }

    #[test]
    fn seed_lineage_record_serde_roundtrip() {
        init_test("seed_lineage_record_serde_roundtrip");
        let plan = SeedPlan::inherit(42, "lin");
        let record = SeedLineageRecord::from_plan(&plan).with_annotation("source", "test");
        let json = serde_json::to_string(&record).unwrap();
        let parsed: SeedLineageRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.canonical_seed, 42);
        assert_eq!(parsed.annotations.get("source").unwrap(), "test");
        crate::test_complete!("seed_lineage_record_serde_roundtrip");
    }

    // --- DualRunScenarioIdentity ---

    #[test]
    fn dual_run_scenario_identity_phase1() {
        init_test("dual_run_scenario_identity_phase1");
        let ident = DualRunScenarioIdentity::phase1(
            "phase1.cancel.race.one_loser",
            "cancellation.race",
            "v1",
            "Race two tasks, cancel loser, verify drain",
            42,
        );
        assert_eq!(ident.schema_version, DUAL_RUN_SCHEMA_VERSION);
        assert_eq!(ident.phase, Phase::Phase1);
        assert_eq!(ident.seed_plan.canonical_seed, 42);
        assert_eq!(
            ident.seed_plan.seed_lineage_id,
            "phase1.cancel.race.one_loser"
        );
        crate::test_complete!("dual_run_scenario_identity_phase1");
    }

    #[test]
    fn dual_run_identity_lab_config() {
        init_test("dual_run_identity_lab_config");
        let ident = DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 0xBEEF);
        let config = ident.to_lab_config();
        assert_eq!(config.seed, 0xBEEF);
        crate::test_complete!("dual_run_identity_lab_config");
    }

    #[test]
    fn dual_run_identity_replay_metadata_lab_live_differ() {
        init_test("dual_run_identity_replay_metadata_lab_live_differ");
        let ident = DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 42);
        let lab_meta = ident.lab_replay_metadata();
        let live_meta = ident.live_replay_metadata();
        assert_eq!(lab_meta.instance.runtime_kind, RuntimeKind::Lab);
        assert_eq!(live_meta.instance.runtime_kind, RuntimeKind::Live);
        // With inherit mode, effective seeds match.
        assert_eq!(lab_meta.effective_seed, live_meta.effective_seed);
        crate::test_complete!("dual_run_identity_replay_metadata_lab_live_differ");
    }

    #[test]
    fn dual_run_identity_family_id() {
        init_test("dual_run_identity_family_id");
        let ident = DualRunScenarioIdentity::phase1("test", "surface", "v1", "desc", 42);
        let fam = ident.family_id();
        assert_eq!(fam.id, "test");
        assert_eq!(fam.surface_id, "surface");
        assert_eq!(fam.surface_contract_version, "v1");
        crate::test_complete!("dual_run_identity_family_id");
    }

    #[test]
    fn dual_run_identity_seed_lineage() {
        init_test("dual_run_identity_seed_lineage");
        let ident = DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 42);
        let lineage = ident.seed_lineage();
        assert!(lineage.seeds_match);
        assert_eq!(lineage.canonical_seed, 42);
        crate::test_complete!("dual_run_identity_seed_lineage");
    }

    #[test]
    fn dual_run_identity_with_seed_plan_override() {
        init_test("dual_run_identity_with_seed_plan_override");
        let plan = SeedPlan::inherit(99, "custom-lineage").with_lab_override(0xFF);
        let ident =
            DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 42).with_seed_plan(plan);
        assert_eq!(ident.seed_plan.canonical_seed, 99);
        assert_eq!(ident.to_lab_config().seed, 0xFF);
        crate::test_complete!("dual_run_identity_with_seed_plan_override");
    }

    #[test]
    fn dual_run_identity_metadata() {
        init_test("dual_run_identity_metadata");
        let ident = DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 42)
            .with_metadata("bead", "2a6k9.2.3")
            .with_metadata("author", "SapphireHill");
        assert_eq!(ident.metadata.get("bead").unwrap(), "2a6k9.2.3");
        assert_eq!(ident.metadata.get("author").unwrap(), "SapphireHill");
        crate::test_complete!("dual_run_identity_metadata");
    }

    #[test]
    fn dual_run_identity_serde_roundtrip() {
        init_test("dual_run_identity_serde_roundtrip");
        let ident = DualRunScenarioIdentity::phase1(
            "phase1.cancel.race.one_loser",
            "cancellation.race",
            "v1",
            "Race two tasks, cancel loser, verify drain",
            42,
        )
        .with_metadata("bead", "2a6k9.2.3");
        let json = serde_json::to_string_pretty(&ident).unwrap();
        let parsed: DualRunScenarioIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.scenario_id, ident.scenario_id);
        assert_eq!(parsed.seed_plan, ident.seed_plan);
        assert_eq!(parsed.phase, Phase::Phase1);
        crate::test_complete!("dual_run_identity_serde_roundtrip");
    }

    // --- Cross-cutting: seed determinism across lab and live ---

    #[test]
    fn same_plan_produces_same_lab_config() {
        init_test("same_plan_produces_same_lab_config");
        let plan = SeedPlan::inherit(0xCAFE_BABE, "determinism-check");
        let c1 = plan.to_lab_config();
        let c2 = plan.to_lab_config();
        assert_eq!(c1.seed, c2.seed);
        assert_eq!(c1.entropy_seed, c2.entropy_seed);
        crate::test_complete!("same_plan_produces_same_lab_config");
    }

    #[test]
    fn inherit_mode_lab_live_seeds_identical() {
        init_test("inherit_mode_lab_live_seeds_identical");
        let plan = SeedPlan::inherit(0xDEAD_BEEF, "identical-check");
        assert_eq!(plan.effective_lab_seed(), plan.effective_live_seed());
        let lab_ent = plan.effective_entropy_seed(plan.effective_lab_seed());
        let live_ent = plan.effective_entropy_seed(plan.effective_live_seed());
        assert_eq!(lab_ent, live_ent);
        crate::test_complete!("inherit_mode_lab_live_seeds_identical");
    }

    #[test]
    fn different_canonical_seeds_produce_different_entropies() {
        init_test("different_canonical_seeds_different_entropies");
        let p1 = SeedPlan::inherit(1, "a");
        let p2 = SeedPlan::inherit(2, "b");
        assert_ne!(
            p1.effective_entropy_seed(p1.effective_lab_seed()),
            p2.effective_entropy_seed(p2.effective_lab_seed())
        );
        crate::test_complete!("different_canonical_seeds_different_entropies");
    }

    // --- Normalized Observable types ---

    fn make_happy_semantics() -> NormalizedSemantics {
        NormalizedSemantics {
            terminal_outcome: TerminalOutcome::ok(),
            cancellation: CancellationRecord::none(),
            loser_drain: LoserDrainRecord::not_applicable(),
            region_close: RegionCloseRecord::quiescent(),
            obligation_balance: ObligationBalanceRecord::zero(),
            resource_surface: ResourceSurfaceRecord::empty("test"),
        }
    }

    fn make_observable(kind: RuntimeKind, semantics: NormalizedSemantics) -> NormalizedObservable {
        let ident = DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 42);
        let prov = match kind {
            RuntimeKind::Lab => ident.lab_replay_metadata(),
            RuntimeKind::Live => ident.live_replay_metadata(),
        };
        NormalizedObservable::new(&ident, kind, semantics, prov)
    }

    #[test]
    fn terminal_outcome_ok_serde() {
        init_test("terminal_outcome_ok_serde");
        let t = TerminalOutcome::ok();
        let json = serde_json::to_string(&t).unwrap();
        let parsed: TerminalOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.class, OutcomeClass::Ok);
        crate::test_complete!("terminal_outcome_ok_serde");
    }

    #[test]
    fn terminal_outcome_cancelled() {
        init_test("terminal_outcome_cancelled");
        let t = TerminalOutcome::cancelled("user_request");
        assert_eq!(t.class, OutcomeClass::Cancelled);
        assert_eq!(t.cancel_reason_class.as_deref(), Some("user_request"));
        crate::test_complete!("terminal_outcome_cancelled");
    }

    #[test]
    fn cancellation_record_none_vs_completed() {
        init_test("cancellation_record_none_vs_completed");
        let none = CancellationRecord::none();
        let completed = CancellationRecord::completed();
        assert!(!none.requested);
        assert!(completed.requested);
        assert!(completed.acknowledged);
        assert!(completed.cleanup_completed);
        assert!(completed.finalization_completed);
        assert_eq!(completed.terminal_phase, CancelTerminalPhase::Completed);
        crate::test_complete!("cancellation_record_none_vs_completed");
    }

    #[test]
    fn loser_drain_complete() {
        init_test("loser_drain_complete");
        let drain = LoserDrainRecord::complete(3);
        assert!(drain.applicable);
        assert_eq!(drain.expected_losers, 3);
        assert_eq!(drain.drained_losers, 3);
        assert_eq!(drain.status, DrainStatus::Complete);
        crate::test_complete!("loser_drain_complete");
    }

    #[test]
    fn obligation_balance_recompute() {
        init_test("obligation_balance_recompute");
        let b = ObligationBalanceRecord {
            reserved: 10,
            committed: 7,
            aborted: 2,
            leaked: 1,
            unresolved: 99, // wrong, should recompute
            balanced: true, // wrong
        }
        .recompute();
        assert_eq!(b.unresolved, 0); // 10 - (7+2+1) = 0
        assert!(!b.balanced); // leaked > 0
        crate::test_complete!("obligation_balance_recompute");
    }

    #[test]
    fn resource_surface_counter_tolerance() {
        init_test("resource_surface_counter_tolerance");
        let rs = ResourceSurfaceRecord::empty("test-surface")
            .with_counter("msgs", 5)
            .with_counter_tolerance("bytes", 100, CounterTolerance::AtLeast);
        assert_eq!(rs.counters["msgs"], 5);
        assert_eq!(rs.tolerances["msgs"], CounterTolerance::Exact);
        assert_eq!(rs.tolerances["bytes"], CounterTolerance::AtLeast);
        crate::test_complete!("resource_surface_counter_tolerance");
    }

    #[test]
    fn normalized_observable_serde_roundtrip() {
        init_test("normalized_observable_serde_roundtrip");
        let obs = make_observable(RuntimeKind::Lab, make_happy_semantics());
        let json = serde_json::to_string_pretty(&obs).unwrap();
        let parsed: NormalizedObservable = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.schema_version, NORMALIZED_OBSERVABLE_SCHEMA_VERSION);
        assert_eq!(parsed.runtime_kind, RuntimeKind::Lab);
        assert_eq!(parsed.semantics.terminal_outcome.class, OutcomeClass::Ok);
        crate::test_complete!("normalized_observable_serde_roundtrip");
    }

    // --- Compare / Verdict ---

    #[test]
    fn compare_identical_observables_passes() {
        init_test("compare_identical_observables_passes");
        let lab = make_observable(RuntimeKind::Lab, make_happy_semantics());
        let live = make_observable(RuntimeKind::Live, make_happy_semantics());
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(verdict.passed);
        assert!(verdict.mismatches.is_empty());
        crate::test_complete!("compare_identical_observables_passes");
    }

    #[test]
    fn compare_outcome_mismatch_fails() {
        init_test("compare_outcome_mismatch_fails");
        let lab_sem = make_happy_semantics();
        let mut live_sem = make_happy_semantics();
        live_sem.terminal_outcome = TerminalOutcome::cancelled("timeout");
        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(!verdict.passed);
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| m.field.contains("terminal_outcome.class"))
        );
        crate::test_complete!("compare_outcome_mismatch_fails");
    }

    #[test]
    fn compare_surface_identity_mismatch_fails() {
        init_test("compare_surface_identity_mismatch_fails");
        let lab = make_observable(RuntimeKind::Lab, make_happy_semantics());
        let mut live = make_observable(RuntimeKind::Live, make_happy_semantics());
        live.surface_id = "different.surface".to_string();
        live.surface_contract_version = "v2".to_string();
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(!verdict.passed);
        assert!(verdict.mismatches.iter().any(|m| m.field == "surface_id"));
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| m.field == "surface_contract_version")
        );
        crate::test_complete!("compare_surface_identity_mismatch_fails");
    }

    #[test]
    fn compare_terminal_reason_and_panic_class_mismatch_fails() {
        init_test("compare_terminal_reason_and_panic_class_mismatch_fails");
        let mut lab_sem = make_happy_semantics();
        lab_sem.terminal_outcome = TerminalOutcome::cancelled("timeout");

        let mut live_sem = make_happy_semantics();
        live_sem.terminal_outcome = TerminalOutcome::cancelled("shutdown");

        let lab = make_observable(RuntimeKind::Lab, lab_sem.clone());
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(!verdict.passed);
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| { m.field == "semantics.terminal_outcome.cancel_reason_class" })
        );

        let mut panic_sem = lab_sem;
        panic_sem.terminal_outcome = TerminalOutcome {
            class: OutcomeClass::Panicked,
            severity: OutcomeClass::Panicked,
            surface_result: None,
            error_class: None,
            cancel_reason_class: None,
            panic_class: Some("panic_a".to_string()),
        };
        let mut other_panic_sem = make_happy_semantics();
        other_panic_sem.terminal_outcome = TerminalOutcome {
            class: OutcomeClass::Panicked,
            severity: OutcomeClass::Panicked,
            surface_result: None,
            error_class: None,
            cancel_reason_class: None,
            panic_class: Some("panic_b".to_string()),
        };
        let panic_lab = make_observable(RuntimeKind::Lab, panic_sem);
        let panic_live = make_observable(RuntimeKind::Live, other_panic_sem);
        let panic_verdict =
            compare_observables(&panic_lab, &panic_live, SeedLineageRecord::from_plan(&plan));
        assert!(!panic_verdict.passed);
        assert!(
            panic_verdict
                .mismatches
                .iter()
                .any(|m| m.field == "semantics.terminal_outcome.panic_class")
        );
        crate::test_complete!("compare_terminal_reason_and_panic_class_mismatch_fails");
    }

    #[test]
    fn compare_obligation_leak_mismatch() {
        init_test("compare_obligation_leak_mismatch");
        let lab_sem = make_happy_semantics();
        let mut live_sem = make_happy_semantics();
        live_sem.obligation_balance = ObligationBalanceRecord {
            reserved: 5,
            committed: 3,
            aborted: 0,
            leaked: 2,
            unresolved: 0,
            balanced: false,
        };
        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(!verdict.passed);
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| m.field.contains("leaked"))
        );
        crate::test_complete!("compare_obligation_leak_mismatch");
    }

    #[test]
    fn compare_obligation_component_mismatch_fails_even_when_balanced() {
        init_test("compare_obligation_component_mismatch_fails_even_when_balanced");
        let mut lab_sem = make_happy_semantics();
        lab_sem.obligation_balance = ObligationBalanceRecord::balanced(3, 3, 0);
        let mut live_sem = make_happy_semantics();
        live_sem.obligation_balance = ObligationBalanceRecord::balanced(3, 2, 1);
        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(!verdict.passed);
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| m.field == "semantics.obligation_balance.committed")
        );
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| m.field == "semantics.obligation_balance.aborted")
        );
        crate::test_complete!("compare_obligation_component_mismatch_fails_even_when_balanced");
    }

    #[test]
    fn compare_resource_counter_exact_mismatch() {
        init_test("compare_resource_counter_exact_mismatch");
        let mut lab_sem = make_happy_semantics();
        lab_sem.resource_surface = ResourceSurfaceRecord::empty("test").with_counter("msgs", 5);
        let mut live_sem = make_happy_semantics();
        live_sem.resource_surface = ResourceSurfaceRecord::empty("test").with_counter("msgs", 3);
        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(!verdict.passed);
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| m.field.contains("counters.msgs"))
        );
        crate::test_complete!("compare_resource_counter_exact_mismatch");
    }

    #[test]
    fn compare_resource_counter_missing_in_live_fails() {
        init_test("compare_resource_counter_missing_in_live_fails");
        let mut lab_sem = make_happy_semantics();
        lab_sem.resource_surface = ResourceSurfaceRecord::empty("test").with_counter("msgs", 0);
        let mut live_sem = make_happy_semantics();
        live_sem.resource_surface = ResourceSurfaceRecord::empty("test");
        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(!verdict.passed);
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| m.description.contains("missing in live observable"))
        );
        crate::test_complete!("compare_resource_counter_missing_in_live_fails");
    }

    #[test]
    fn compare_resource_counter_missing_in_lab_fails() {
        init_test("compare_resource_counter_missing_in_lab_fails");
        let mut lab_sem = make_happy_semantics();
        lab_sem.resource_surface = ResourceSurfaceRecord::empty("test");
        let mut live_sem = make_happy_semantics();
        live_sem.resource_surface = ResourceSurfaceRecord::empty("test").with_counter("msgs", 0);
        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(!verdict.passed);
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| m.description.contains("present in live but not in lab"))
        );
        crate::test_complete!("compare_resource_counter_missing_in_lab_fails");
    }

    #[test]
    fn compare_resource_tolerance_mismatch_fails() {
        init_test("compare_resource_tolerance_mismatch_fails");
        let mut lab_sem = make_happy_semantics();
        lab_sem.resource_surface = ResourceSurfaceRecord::empty("test").with_counter_tolerance(
            "msgs",
            5,
            CounterTolerance::Exact,
        );
        let mut live_sem = make_happy_semantics();
        live_sem.resource_surface = ResourceSurfaceRecord::empty("test").with_counter_tolerance(
            "msgs",
            5,
            CounterTolerance::Unsupported,
        );
        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(!verdict.passed);
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| m.field == "semantics.resource_surface.tolerances.msgs")
        );
        crate::test_complete!("compare_resource_tolerance_mismatch_fails");
    }

    #[test]
    fn compare_resource_counter_at_least_passes() {
        init_test("compare_resource_counter_at_least_passes");
        let mut lab_sem = make_happy_semantics();
        lab_sem.resource_surface = ResourceSurfaceRecord::empty("test").with_counter_tolerance(
            "msgs",
            5,
            CounterTolerance::AtLeast,
        );
        let mut live_sem = make_happy_semantics();
        live_sem.resource_surface = ResourceSurfaceRecord::empty("test").with_counter_tolerance(
            "msgs",
            7,
            CounterTolerance::AtLeast,
        );
        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(verdict.passed);
        crate::test_complete!("compare_resource_counter_at_least_passes");
    }

    #[test]
    fn compare_region_close_counts_mismatch_fails() {
        init_test("compare_region_close_counts_mismatch_fails");
        let lab_sem = make_happy_semantics();
        let mut live_sem = make_happy_semantics();
        live_sem.region_close.live_children = 1;
        live_sem.region_close.finalizers_pending = 2;
        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(!verdict.passed);
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| m.field == "semantics.region_close.live_children")
        );
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| m.field == "semantics.region_close.finalizers_pending")
        );
        crate::test_complete!("compare_region_close_counts_mismatch_fails");
    }

    #[test]
    fn compare_region_close_ignores_non_quiescent_root_state_hint_mismatch() {
        init_test("compare_region_close_ignores_non_quiescent_root_state_hint_mismatch");
        let mut lab_sem = make_happy_semantics();
        lab_sem.region_close = RegionCloseRecord {
            root_state: RegionState::Open,
            quiescent: false,
            live_children: 0,
            finalizers_pending: 0,
            close_completed: false,
        };

        let mut live_sem = make_happy_semantics();
        live_sem.region_close = RegionCloseRecord {
            root_state: RegionState::Finalizing,
            quiescent: false,
            live_children: 0,
            finalizers_pending: 0,
            close_completed: false,
        };

        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));

        assert!(verdict.passed);
        assert!(
            !verdict
                .mismatches
                .iter()
                .any(|m| m.field == "semantics.region_close.root_state")
        );
        crate::test_complete!(
            "compare_region_close_ignores_non_quiescent_root_state_hint_mismatch"
        );
    }

    #[test]
    fn compare_region_close_ignores_unknown_non_quiescent_lab_counts() {
        init_test("compare_region_close_ignores_unknown_non_quiescent_lab_counts");
        let mut lab_sem = make_happy_semantics();
        lab_sem.region_close = RegionCloseRecord {
            root_state: RegionState::Closing,
            quiescent: false,
            live_children: 0,
            finalizers_pending: 0,
            close_completed: false,
        };

        let mut live_sem = make_happy_semantics();
        live_sem.region_close = RegionCloseRecord {
            root_state: RegionState::Draining,
            quiescent: false,
            live_children: 1,
            finalizers_pending: 0,
            close_completed: false,
        };

        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));

        assert!(verdict.passed);
        crate::test_complete!("compare_region_close_ignores_unknown_non_quiescent_lab_counts");
    }

    #[test]
    fn compare_loser_drain_ignores_unknown_lab_counts_from_oracle_pass() {
        init_test("compare_loser_drain_ignores_unknown_lab_counts_from_oracle_pass");
        let mut lab_sem = make_happy_semantics();
        lab_sem.loser_drain = LoserDrainRecord {
            applicable: true,
            expected_losers: 0,
            drained_losers: 0,
            status: DrainStatus::Complete,
            evidence: Some("oracle.loser_drain.passed".to_string()),
        };

        let mut live_sem = make_happy_semantics();
        live_sem.loser_drain = LoserDrainRecord::complete(2);

        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));

        assert!(verdict.passed);
        crate::test_complete!("compare_loser_drain_ignores_unknown_lab_counts_from_oracle_pass");
    }

    #[test]
    fn compare_loser_drain_unknown_lab_counts_still_fail_on_status_mismatch() {
        init_test("compare_loser_drain_unknown_lab_counts_still_fail_on_status_mismatch");
        let mut lab_sem = make_happy_semantics();
        lab_sem.loser_drain = LoserDrainRecord {
            applicable: true,
            expected_losers: 0,
            drained_losers: 0,
            status: DrainStatus::Complete,
            evidence: Some("oracle.loser_drain.passed".to_string()),
        };

        let mut live_sem = make_happy_semantics();
        live_sem.loser_drain = LoserDrainRecord {
            applicable: true,
            expected_losers: 2,
            drained_losers: 1,
            status: DrainStatus::Incomplete,
            evidence: Some("task_handle.join".to_string()),
        };

        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));

        assert!(!verdict.passed);
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| m.field == "semantics.loser_drain.status")
        );
        crate::test_complete!(
            "compare_loser_drain_unknown_lab_counts_still_fail_on_status_mismatch"
        );
    }

    #[test]
    fn compare_cancellation_mismatch() {
        init_test("compare_cancellation_mismatch");
        let mut lab_sem = make_happy_semantics();
        lab_sem.cancellation = CancellationRecord::completed();
        let live_sem = make_happy_semantics(); // no cancellation
        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(!verdict.passed);
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| m.field.contains("cancellation"))
        );
        crate::test_complete!("compare_cancellation_mismatch");
    }

    #[test]
    fn verdict_display_pass() {
        init_test("verdict_display_pass");
        let lab = make_observable(RuntimeKind::Lab, make_happy_semantics());
        let live = make_observable(RuntimeKind::Live, make_happy_semantics());
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        let summary = verdict.summary();
        assert!(summary.contains("PASS"));
        crate::test_complete!("verdict_display_pass");
    }

    #[test]
    fn verdict_display_fail() {
        init_test("verdict_display_fail");
        let lab_sem = make_happy_semantics();
        let mut live_sem = make_happy_semantics();
        live_sem.region_close.quiescent = false;
        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        let summary = verdict.summary();
        assert!(summary.contains("FAIL"));
        assert!(summary.contains("mismatch"));
        crate::test_complete!("verdict_display_fail");
    }

    // --- Core Invariant Checks ---

    #[test]
    fn check_core_invariants_all_pass() {
        init_test("check_core_invariants_all_pass");
        let obs = make_observable(RuntimeKind::Lab, make_happy_semantics());
        let violations = check_core_invariants(&obs);
        assert!(violations.is_empty());
        crate::test_complete!("check_core_invariants_all_pass");
    }

    #[test]
    fn check_core_invariants_obligation_leak() {
        init_test("check_core_invariants_obligation_leak");
        let mut sem = make_happy_semantics();
        sem.obligation_balance.leaked = 1;
        sem.obligation_balance.balanced = false;
        let obs = make_observable(RuntimeKind::Lab, sem);
        let violations = check_core_invariants(&obs);
        assert!(!violations.is_empty());
        assert!(violations[0].contains("leaked"));
        crate::test_complete!("check_core_invariants_obligation_leak");
    }

    #[test]
    fn check_core_invariants_not_quiescent() {
        init_test("check_core_invariants_not_quiescent");
        let mut sem = make_happy_semantics();
        sem.region_close.quiescent = false;
        sem.region_close.live_children = 2;
        let obs = make_observable(RuntimeKind::Lab, sem);
        let violations = check_core_invariants(&obs);
        assert!(violations.iter().any(|v| v.contains("quiescent")));
        crate::test_complete!("check_core_invariants_not_quiescent");
    }

    #[test]
    fn check_core_invariants_incomplete_drain() {
        init_test("check_core_invariants_incomplete_drain");
        let mut sem = make_happy_semantics();
        sem.loser_drain = LoserDrainRecord {
            applicable: true,
            expected_losers: 3,
            drained_losers: 1,
            status: DrainStatus::Incomplete,
            evidence: None,
        };
        let obs = make_observable(RuntimeKind::Lab, sem);
        let violations = check_core_invariants(&obs);
        assert!(violations.iter().any(|v| v.contains("drain")));
        crate::test_complete!("check_core_invariants_incomplete_drain");
    }

    #[test]
    fn check_core_invariants_cancel_incomplete() {
        init_test("check_core_invariants_cancel_incomplete");
        let mut sem = make_happy_semantics();
        sem.cancellation.requested = true;
        sem.cancellation.cleanup_completed = false;
        sem.cancellation.terminal_phase = CancelTerminalPhase::Cancelling;
        let obs = make_observable(RuntimeKind::Lab, sem);
        let violations = check_core_invariants(&obs);
        assert!(
            violations
                .iter()
                .any(|v| v.contains("Cancellation cleanup incomplete"))
        );
        assert!(
            !violations
                .iter()
                .any(|v| v.contains("Cancellation finalization incomplete")),
            "finalization should not be required before cleanup completes"
        );
        crate::test_complete!("check_core_invariants_cancel_incomplete");
    }

    #[test]
    fn check_core_invariants_cancel_finalization_incomplete() {
        init_test("check_core_invariants_cancel_finalization_incomplete");
        let mut sem = make_happy_semantics();
        sem.cancellation.requested = true;
        sem.cancellation.cleanup_completed = true;
        sem.cancellation.finalization_completed = false;
        sem.cancellation.terminal_phase = CancelTerminalPhase::Finalizing;
        let obs = make_observable(RuntimeKind::Lab, sem);
        let violations = check_core_invariants(&obs);
        assert!(
            violations
                .iter()
                .any(|v| v.contains("Cancellation finalization incomplete"))
        );
        crate::test_complete!("check_core_invariants_cancel_finalization_incomplete");
    }

    // --- assert_semantics ---

    #[test]
    fn assert_semantics_identical_passes() {
        init_test("assert_semantics_identical_passes");
        let sem = make_happy_semantics();
        let mismatches = assert_semantics(&sem, &sem);
        assert!(mismatches.is_empty());
        crate::test_complete!("assert_semantics_identical_passes");
    }

    #[test]
    fn assert_semantics_detects_diff() {
        init_test("assert_semantics_detects_diff");
        let expected = make_happy_semantics();
        let mut actual = make_happy_semantics();
        actual.terminal_outcome = TerminalOutcome::err("network_error");
        let mismatches = assert_semantics(&actual, &expected);
        assert!(!mismatches.is_empty());
        crate::test_complete!("assert_semantics_detects_diff");
    }

    // --- DualRunHarness ---

    #[test]
    fn harness_identical_runs_pass() {
        init_test("harness_identical_runs_pass");
        let result = DualRunHarness::phase1(
            "test.happy_path",
            "test.surface",
            "v1",
            "Both sides produce identical semantics",
            42,
        )
        .lab(|_config| make_happy_semantics())
        .live(|_seed, _entropy| make_happy_semantics())
        .run();

        assert!(result.passed());
        assert!(result.verdict.is_equivalent());
        assert!(result.lab_invariant_violations.is_empty());
        assert!(result.live_invariant_violations.is_empty());
        crate::test_complete!("harness_identical_runs_pass");
    }

    #[test]
    fn harness_outcome_mismatch_fails() {
        init_test("harness_outcome_mismatch_fails");
        let result = DualRunHarness::phase1(
            "test.mismatch",
            "test.surface",
            "v1",
            "Lab succeeds, live cancels",
            42,
        )
        .lab(|_config| make_happy_semantics())
        .live(|_seed, _entropy| {
            let mut sem = make_happy_semantics();
            sem.terminal_outcome = TerminalOutcome::cancelled("timeout");
            sem
        })
        .run();

        assert!(!result.passed());
        assert!(!result.verdict.is_equivalent());
        crate::test_complete!("harness_outcome_mismatch_fails");
    }

    #[test]
    fn harness_lab_invariant_violation_fails() {
        init_test("harness_lab_invariant_violation_fails");
        let result = DualRunHarness::phase1(
            "test.leak",
            "test.surface",
            "v1",
            "Lab leaks obligations",
            42,
        )
        .lab(|_config| {
            let mut sem = make_happy_semantics();
            sem.obligation_balance.leaked = 1;
            sem.obligation_balance.balanced = false;
            sem
        })
        .live(|_seed, _entropy| {
            let mut sem = make_happy_semantics();
            sem.obligation_balance.leaked = 1;
            sem.obligation_balance.balanced = false;
            sem
        })
        .run();

        // Semantics match (both leak), but invariant check catches it.
        assert!(result.verdict.is_equivalent());
        assert!(!result.lab_invariant_violations.is_empty());
        assert!(!result.passed()); // Failed due to invariant violations.
        crate::test_complete!("harness_lab_invariant_violation_fails");
    }

    #[test]
    fn harness_receives_correct_seeds() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};
        init_test("harness_receives_correct_seeds");

        let captured_lab_seed = Arc::new(AtomicU64::new(0));
        let captured_live_seed = Arc::new(AtomicU64::new(0));
        let lab_clone = Arc::clone(&captured_lab_seed);
        let live_clone = Arc::clone(&captured_live_seed);

        let result = DualRunHarness::phase1("test.seeds", "s", "v1", "d", 0xBEEF)
            .lab(move |config| {
                lab_clone.store(config.seed, Ordering::Relaxed);
                make_happy_semantics()
            })
            .live(move |seed, _entropy| {
                live_clone.store(seed, Ordering::Relaxed);
                make_happy_semantics()
            })
            .run();

        assert!(result.passed());
        assert_eq!(captured_lab_seed.load(Ordering::Relaxed), 0xBEEF);
        assert_eq!(captured_live_seed.load(Ordering::Relaxed), 0xBEEF);
        crate::test_complete!("harness_receives_correct_seeds");
    }

    #[test]
    fn harness_with_custom_seed_plan() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};
        init_test("harness_with_custom_seed_plan");

        let captured_lab = Arc::new(AtomicU64::new(0));
        let captured_live = Arc::new(AtomicU64::new(0));
        let lab_c = Arc::clone(&captured_lab);
        let live_c = Arc::clone(&captured_live);

        let plan = SeedPlan::inherit(42, "custom")
            .with_lab_override(0xCAFE)
            .with_live_override(0xFACE);

        let result = DualRunHarness::phase1("test", "s", "v1", "d", 42)
            .with_seed_plan(plan)
            .lab(move |config| {
                lab_c.store(config.seed, Ordering::Relaxed);
                make_happy_semantics()
            })
            .live(move |seed, _entropy| {
                live_c.store(seed, Ordering::Relaxed);
                make_happy_semantics()
            })
            .run();

        assert_eq!(captured_lab.load(Ordering::Relaxed), 0xCAFE);
        assert_eq!(captured_live.load(Ordering::Relaxed), 0xFACE);
        // Semantics match despite different seeds.
        assert!(result.verdict.is_equivalent());
        // But seeds don't match.
        assert!(!result.seed_lineage.seeds_match);
        crate::test_complete!("harness_with_custom_seed_plan");
    }

    #[test]
    fn harness_from_identity() {
        init_test("harness_from_identity");
        let ident = DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 99);
        let result = DualRunHarness::from_identity(ident)
            .lab(|_| make_happy_semantics())
            .live(|_, _| make_happy_semantics())
            .run();
        assert!(result.passed());
        assert_eq!(result.verdict.scenario_id, "test");
        crate::test_complete!("harness_from_identity");
    }

    #[test]
    fn dual_run_result_display() {
        init_test("dual_run_result_display");
        let result = DualRunHarness::phase1("test", "s", "v1", "d", 42)
            .lab(|_| make_happy_semantics())
            .live(|_, _| make_happy_semantics())
            .run();
        let summary = format!("{result}");
        assert!(summary.contains("PASS"));
        crate::test_complete!("dual_run_result_display");
    }

    #[test]
    fn harness_noise_notes_classify_scheduler_noise() {
        init_test("harness_noise_notes_classify_scheduler_noise");
        let ident = DualRunScenarioIdentity::phase1("test.noise", "test.surface", "v1", "d", 42);
        let live_ident = ident.clone();

        let result = DualRunHarness::from_identity(ident)
            .lab(|_| make_happy_semantics())
            .live_result(move |_, _| {
                let mut result = run_live_adapter(&live_ident, |_config, witness| {
                    witness.set_outcome(TerminalOutcome::ok());
                    witness.note_nondeterminism("thread scheduling");
                });
                result.semantics.resource_surface = ResourceSurfaceRecord::empty("test");
                result
            })
            .run();

        assert!(result.passed());
        assert_eq!(
            result.policy.provisional_class,
            ProvisionalDivergenceClass::SchedulerNoiseSuspected
        );
        assert_eq!(
            result.policy.rerun_decision,
            RerunDecision::LiveConfirmations { additional_runs: 2 }
        );
        assert_eq!(
            result.policy.scheduler_noise_class,
            SchedulerNoiseClass::NondeterminismNotesOnly
        );
        crate::test_complete!("harness_noise_notes_classify_scheduler_noise");
    }

    #[test]
    fn classify_scheduler_noise_prefers_hash_drift_over_notes() {
        init_test("classify_scheduler_noise_prefers_hash_drift_over_notes");
        let lab = make_observable(RuntimeKind::Lab, make_happy_semantics());
        let mut live = make_observable(RuntimeKind::Live, make_happy_semantics());
        let mut lab_prov = lab.provenance.clone();
        lab_prov.schedule_hash = Some(0xAAAA);
        let mut live_prov = live.provenance.clone();
        live_prov.schedule_hash = Some(0xBBBB);
        live_prov.nondeterminism_notes = vec!["thread scheduling".to_string()];

        let lab = NormalizedObservable {
            provenance: lab_prov,
            ..lab
        };
        live.provenance = live_prov;

        assert_eq!(
            classify_scheduler_noise(&lab, &live),
            SchedulerNoiseClass::ScheduleHashDrift
        );
        crate::test_complete!("classify_scheduler_noise_prefers_hash_drift_over_notes");
    }

    #[test]
    fn harness_semantic_mismatch_policy_requests_reruns() {
        init_test("harness_semantic_mismatch_policy_requests_reruns");
        let result = DualRunHarness::phase1("test.mismatch.policy", "test.surface", "v1", "d", 42)
            .lab(|_| make_happy_semantics())
            .live(|_, _| {
                let mut sem = make_happy_semantics();
                sem.terminal_outcome = TerminalOutcome::err("network_error");
                sem
            })
            .run();

        assert_eq!(
            result.policy.provisional_class,
            ProvisionalDivergenceClass::SemanticMismatchAdmittedSurface
        );
        assert_eq!(
            result.policy.rerun_decision,
            RerunDecision::DeterministicLabReplayAndLiveConfirmations {
                additional_live_runs: 2,
            }
        );
        assert_eq!(result.policy.suggested_final_class, None);
        crate::test_complete!("harness_semantic_mismatch_policy_requests_reruns");
    }

    #[test]
    fn harness_unsupported_surface_policy_short_circuits() {
        init_test("harness_unsupported_surface_policy_short_circuits");
        let ident =
            DualRunScenarioIdentity::phase1("test.unsupported", "browser.surface", "v1", "d", 42)
                .with_metadata("eligibility_verdict", "unsupported")
                .with_metadata("unsupported_reason", "browser timing surface not admitted");

        let result = DualRunHarness::from_identity(ident)
            .lab(|_| make_happy_semantics())
            .live(|_, _| {
                let mut sem = make_happy_semantics();
                sem.terminal_outcome = TerminalOutcome::err("unsupported_surface");
                sem
            })
            .run();

        assert_eq!(
            result.policy.provisional_class,
            ProvisionalDivergenceClass::UnsupportedSurface
        );
        assert_eq!(result.policy.rerun_decision, RerunDecision::None);
        assert_eq!(
            result.policy.suggested_final_class,
            Some(FinalDivergenceClass::UnsupportedSurface)
        );
        crate::test_complete!("harness_unsupported_surface_policy_short_circuits");
    }

    #[test]
    fn harness_insufficient_observability_policy_marks_gap() {
        init_test("harness_insufficient_observability_policy_marks_gap");
        let ident =
            DualRunScenarioIdentity::phase1("test.observability", "timer.surface", "v1", "d", 42)
                .with_metadata("observability_status", "blocked_missing_live_timer_surface");

        let result = DualRunHarness::from_identity(ident)
            .lab(|_| {
                let mut sem = make_happy_semantics();
                sem.resource_surface =
                    ResourceSurfaceRecord::empty("timer.surface").with_counter("timeouts", 1);
                sem
            })
            .live(|_, _| {
                let mut sem = make_happy_semantics();
                sem.resource_surface = ResourceSurfaceRecord::empty("timer.surface");
                sem
            })
            .run();

        assert_eq!(
            result.policy.provisional_class,
            ProvisionalDivergenceClass::InsufficientObservability
        );
        assert_eq!(
            result.policy.rerun_decision,
            RerunDecision::ConfirmationIfRicherInstrumentationEnabled { additional_runs: 1 }
        );
        assert_eq!(
            result.policy.suggested_final_class,
            Some(FinalDivergenceClass::InsufficientObservability)
        );
        crate::test_complete!("harness_insufficient_observability_policy_marks_gap");
    }

    #[test]
    fn harness_blocked_missing_observability_gate_is_not_a_pass() {
        init_test("harness_blocked_missing_observability_gate_is_not_a_pass");
        let ident = DualRunScenarioIdentity::phase1(
            "test.observability.gate",
            "timer.surface",
            "v1",
            "d",
            42,
        )
        .with_metadata("eligibility_verdict", "blocked_missing_observability");

        let result = DualRunHarness::from_identity(ident)
            .lab(|_| make_happy_semantics())
            .live(|_, _| make_happy_semantics())
            .run();

        assert_eq!(
            result.policy.provisional_class,
            ProvisionalDivergenceClass::InsufficientObservability
        );
        assert_eq!(
            result.policy.rerun_decision,
            RerunDecision::ConfirmationIfRicherInstrumentationEnabled { additional_runs: 1 }
        );
        assert_eq!(
            result.policy.suggested_final_class,
            Some(FinalDivergenceClass::InsufficientObservability)
        );
        crate::test_complete!("harness_blocked_missing_observability_gate_is_not_a_pass");
    }

    #[test]
    fn harness_bridge_only_downgrade_can_still_be_an_admitted_surface() {
        init_test("harness_bridge_only_downgrade_can_still_be_an_admitted_surface");
        let ident = DualRunScenarioIdentity::phase1(
            "test.bridge_only_admitted",
            "browser.surface",
            "v1",
            "bridge-only downgrade remains comparable when admitted",
            42,
        )
        .with_metadata("eligibility_verdict", "eligible_for_pilot")
        .with_metadata("support_class", "bridge_only")
        .with_metadata("reason_code", "downgrade_to_server_bridge");

        let result = DualRunHarness::from_identity(ident)
            .lab(|_| make_happy_semantics())
            .live(|_, _| make_happy_semantics())
            .run();

        assert!(result.passed(), "{}", result.summary());
        assert_eq!(
            result.policy.provisional_class,
            ProvisionalDivergenceClass::Pass
        );
        assert_eq!(result.policy.rerun_decision, RerunDecision::None);
        assert_eq!(result.policy.suggested_final_class, None);
        crate::test_complete!("harness_bridge_only_downgrade_can_still_be_an_admitted_surface");
    }

    #[test]
    fn harness_bridge_only_without_downgrade_reason_stays_unsupported() {
        init_test("harness_bridge_only_without_downgrade_reason_stays_unsupported");
        let ident = DualRunScenarioIdentity::phase1(
            "test.bridge_only_invalid_reason",
            "browser.surface",
            "v1",
            "bridge-only without a supported downgrade reason must fail closed",
            42,
        )
        .with_metadata("support_class", "bridge_only")
        .with_metadata("reason_code", "unsupported_runtime_context")
        .with_metadata(
            "unsupported_reason",
            "non-browser runtime context has no admitted downgrade lane",
        );

        let result = DualRunHarness::from_identity(ident)
            .lab(|_| make_happy_semantics())
            .live(|_, _| make_happy_semantics())
            .run();

        assert_eq!(
            result.policy.provisional_class,
            ProvisionalDivergenceClass::UnsupportedSurface
        );
        assert_eq!(result.policy.rerun_decision, RerunDecision::None);
        assert_eq!(
            result.policy.suggested_final_class,
            Some(FinalDivergenceClass::UnsupportedSurface)
        );
        crate::test_complete!("harness_bridge_only_without_downgrade_reason_stays_unsupported");
    }

    #[test]
    fn harness_eligible_gate_does_not_override_unsupported_support_class() {
        init_test("harness_eligible_gate_does_not_override_unsupported_support_class");
        let ident = DualRunScenarioIdentity::phase1(
            "test.eligible_gate_conflict",
            "browser.surface",
            "v1",
            "contradictory unsupported support class must fail closed",
            42,
        )
        .with_metadata("eligibility_verdict", "eligible_for_pilot")
        .with_metadata("support_class", "unsupported")
        .with_metadata(
            "unsupported_reason",
            "shared worker direct runtime not shipped",
        );

        let result = DualRunHarness::from_identity(ident)
            .lab(|_| make_happy_semantics())
            .live(|_, _| make_happy_semantics())
            .run();

        assert_eq!(
            result.policy.provisional_class,
            ProvisionalDivergenceClass::UnsupportedSurface
        );
        assert_eq!(result.policy.rerun_decision, RerunDecision::None);
        assert_eq!(
            result.policy.suggested_final_class,
            Some(FinalDivergenceClass::UnsupportedSurface)
        );
        crate::test_complete!("harness_eligible_gate_does_not_override_unsupported_support_class");
    }

    #[test]
    fn harness_blocked_missing_verification_gate_stays_unsupported() {
        init_test("harness_blocked_missing_verification_gate_stays_unsupported");
        let ident = DualRunScenarioIdentity::phase1(
            "test.verification.gate",
            "browser.surface",
            "v1",
            "d",
            42,
        )
        .with_metadata("eligibility_verdict", "blocked_missing_verification")
        .with_metadata("support_class", "bridge_only")
        .with_metadata("reason_code", "downgrade_to_server_bridge");

        let result = DualRunHarness::from_identity(ident)
            .lab(|_| make_happy_semantics())
            .live(|_, _| make_happy_semantics())
            .run();

        assert_eq!(
            result.policy.provisional_class,
            ProvisionalDivergenceClass::UnsupportedSurface
        );
        assert_eq!(result.policy.rerun_decision, RerunDecision::None);
        assert_eq!(
            result.policy.suggested_final_class,
            Some(FinalDivergenceClass::UnsupportedSurface)
        );
        crate::test_complete!("harness_blocked_missing_verification_gate_stays_unsupported");
    }

    #[test]
    fn harness_hard_contract_break_policy_short_circuits() {
        init_test("harness_hard_contract_break_policy_short_circuits");
        let result = DualRunHarness::phase1("test.hard_break", "test.surface", "v1", "d", 42)
            .lab(|_| make_happy_semantics())
            .live(|_, _| {
                let mut sem = make_happy_semantics();
                sem.obligation_balance.leaked = 1;
                sem.obligation_balance.balanced = false;
                sem
            })
            .run();

        assert_eq!(
            result.policy.provisional_class,
            ProvisionalDivergenceClass::HardContractBreak
        );
        assert_eq!(result.policy.rerun_decision, RerunDecision::None);
        assert_eq!(
            result.policy.suggested_final_class,
            Some(FinalDivergenceClass::RuntimeSemanticBug)
        );
        crate::test_complete!("harness_hard_contract_break_policy_short_circuits");
    }

    #[test]
    #[should_panic(expected = "Dual-run test failed")]
    fn assert_dual_run_passes_panics_on_failure() {
        init_test("assert_dual_run_passes_panics_on_failure");
        let result = DualRunHarness::phase1("test", "s", "v1", "d", 42)
            .lab(|_| make_happy_semantics())
            .live(|_, _| {
                let mut sem = make_happy_semantics();
                sem.terminal_outcome = TerminalOutcome::err("oops");
                sem
            })
            .run();
        assert_dual_run_passes(&result);
    }

    // --- LiveRunnerAdapter ---

    #[test]
    fn live_runner_config_from_identity() {
        init_test("live_runner_config_from_identity");
        let ident = DualRunScenarioIdentity::phase1("test", "surface", "v1", "d", 0xBEEF);
        let config = LiveRunnerConfig::from_identity(&ident);
        assert_eq!(config.seed, 0xBEEF);
        assert_eq!(config.profile, LiveExecutionProfile::CurrentThread);
        assert_eq!(config.scenario_id, "test");
        assert_eq!(config.surface_id, "surface");
        crate::test_complete!("live_runner_config_from_identity");
    }

    #[test]
    fn live_runner_config_from_plan() {
        init_test("live_runner_config_from_plan");
        let plan = SeedPlan::inherit(42, "lineage").with_live_override(0xCAFE);
        let config = LiveRunnerConfig::from_plan(&plan, "scenario", "surface");
        assert_eq!(config.seed, 0xCAFE);
        assert_eq!(config.seed_lineage_id, "lineage");
        crate::test_complete!("live_runner_config_from_plan");
    }

    #[test]
    fn live_runner_config_display() {
        init_test("live_runner_config_display");
        let ident = DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 42);
        let config = LiveRunnerConfig::from_identity(&ident);
        let s = format!("{config}");
        assert!(s.contains("test"));
        assert!(s.contains("current_thread"));
        crate::test_complete!("live_runner_config_display");
    }

    #[test]
    fn live_witness_collector_defaults() {
        init_test("live_witness_collector_defaults");
        let witness = LiveWitnessCollector::new("test.surface");
        let sem = witness.finalize();
        assert_eq!(sem.terminal_outcome.class, OutcomeClass::Ok);
        assert!(sem.region_close.quiescent);
        assert!(sem.obligation_balance.balanced);
        assert_eq!(sem.loser_drain.status, DrainStatus::NotApplicable);
        assert_eq!(sem.resource_surface.contract_scope, "test.surface");
        crate::test_complete!("live_witness_collector_defaults");
    }

    #[test]
    fn live_witness_collector_records_evidence() {
        init_test("live_witness_collector_records_evidence");
        let mut witness = LiveWitnessCollector::new("test");
        witness.set_outcome(TerminalOutcome::cancelled("timeout"));
        witness.set_cancellation(CancellationRecord::completed());
        witness.set_loser_drain(LoserDrainRecord::complete(2));
        witness.set_obligation_balance(ObligationBalanceRecord::balanced(5, 4, 1));
        witness.record_counter("msgs_sent", 10);
        witness.record_counter_with_tolerance("bytes", 1024, CounterTolerance::AtLeast);
        witness.note_nondeterminism("scheduler ordering may vary");

        assert_eq!(witness.nondeterminism_notes().len(), 1);

        let sem = witness.finalize();
        assert_eq!(sem.terminal_outcome.class, OutcomeClass::Cancelled);
        assert!(sem.cancellation.requested);
        assert_eq!(sem.loser_drain.drained_losers, 2);
        assert_eq!(sem.obligation_balance.committed, 4);
        assert_eq!(sem.resource_surface.counters["msgs_sent"], 10);
        assert_eq!(
            sem.resource_surface.tolerances["bytes"],
            CounterTolerance::AtLeast
        );
        crate::test_complete!("live_witness_collector_records_evidence");
    }

    #[test]
    fn run_live_adapter_happy_path() {
        init_test("run_live_adapter_happy_path");
        let ident = DualRunScenarioIdentity::phase1(
            "test.happy",
            "test.surface",
            "v1",
            "Happy path live adapter test",
            42,
        );
        let result = run_live_adapter(&ident, |config, witness| {
            assert_eq!(config.seed, 42);
            assert_eq!(config.profile, LiveExecutionProfile::CurrentThread);
            witness.set_outcome(TerminalOutcome::ok());
            witness.record_counter("items_processed", 5);
        });
        assert_eq!(result.semantics.terminal_outcome.class, OutcomeClass::Ok);
        assert_eq!(
            result.semantics.resource_surface.counters["items_processed"],
            5
        );
        assert_eq!(result.metadata.config.scenario_id, "test.happy");
        assert!(result.metadata.nondeterminism_notes.is_empty());
        assert_eq!(
            result
                .metadata
                .capture_manifest
                .describe_field_capture("semantics.terminal_outcome.class")
                .as_deref(),
            Some("observed via witness.set_outcome")
        );
        assert_eq!(
            result
                .metadata
                .capture_manifest
                .describe_field_capture("semantics.resource_surface.counters.items_processed")
                .as_deref(),
            Some("observed via witness.record_counter")
        );
        crate::test_complete!("run_live_adapter_happy_path");
    }

    #[test]
    fn run_live_adapter_with_nondeterminism() {
        init_test("run_live_adapter_with_nondeterminism");
        let ident = DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 42);
        let result = run_live_adapter(&ident, |_config, witness| {
            witness.note_nondeterminism("timer resolution varies");
            witness.note_nondeterminism("thread scheduling");
        });
        assert_eq!(result.metadata.nondeterminism_notes.len(), 2);
        assert_eq!(
            result.metadata.replay.nondeterminism_notes,
            result.metadata.nondeterminism_notes
        );
        crate::test_complete!("run_live_adapter_with_nondeterminism");
    }

    #[test]
    fn run_live_adapter_cancellation_scenario() {
        init_test("run_live_adapter_cancellation_scenario");
        let ident = DualRunScenarioIdentity::phase1(
            "cancel.race",
            "cancellation.race",
            "v1",
            "Cancel and drain",
            0xDEAD,
        );
        let result = run_live_adapter(&ident, |config, witness| {
            assert_eq!(config.seed, 0xDEAD);
            witness.set_outcome(TerminalOutcome::ok());
            witness.set_cancellation(CancellationRecord::completed());
            witness.set_loser_drain(LoserDrainRecord::complete(1));
        });
        assert!(result.semantics.cancellation.requested);
        assert!(result.semantics.cancellation.cleanup_completed);
        assert_eq!(result.semantics.loser_drain.status, DrainStatus::Complete);
        assert_eq!(
            result.metadata.replay.instance.runtime_kind,
            RuntimeKind::Live
        );
        assert_eq!(
            result
                .metadata
                .capture_manifest
                .describe_field_capture("semantics.cancellation.checkpoint_observed")
                .as_deref(),
            Some("observed via witness.set_cancellation")
        );
        crate::test_complete!("run_live_adapter_cancellation_scenario");
    }

    #[test]
    fn run_live_adapter_metadata_serde() {
        init_test("run_live_adapter_metadata_serde");
        let ident = DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 42);
        let result = run_live_adapter(&ident, |_, _| {});
        let json = serde_json::to_string_pretty(&result.metadata).unwrap();
        let parsed: LiveRunMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.config.seed, 42);
        assert_eq!(parsed.config.profile, LiveExecutionProfile::CurrentThread);
        assert_eq!(
            parsed
                .capture_manifest
                .describe_field_capture("semantics.region_close.quiescent")
                .as_deref(),
            Some("inferred via run_live_adapter.default_quiescent")
        );
        crate::test_complete!("run_live_adapter_metadata_serde");
    }

    #[test]
    fn live_adapter_integrates_with_harness() {
        init_test("live_adapter_integrates_with_harness");
        // Demonstrates the full pattern: use run_live_adapter inside
        // DualRunHarness.live() closure for structured live evidence.
        let result = DualRunHarness::phase1(
            "integration.test",
            "test.surface",
            "v1",
            "Full integration of live adapter with harness",
            0xBEEF,
        )
        .lab(|_config| make_happy_semantics())
        .live(|seed, _entropy| {
            let ident = DualRunScenarioIdentity::phase1(
                "integration.test",
                "test.surface",
                "v1",
                "d",
                seed,
            );
            let live_result = run_live_adapter(&ident, |_config, witness| {
                witness.set_outcome(TerminalOutcome::ok());
                witness.record_counter("items", 3);
            });
            live_result.semantics
        })
        .run();

        // Resource counter won't match lab (which has no counters),
        // but that's expected — live has extra counters.
        // The harness detects this properly.
        assert!(!result.verdict.passed); // Different resource surfaces
        crate::test_complete!("live_adapter_integrates_with_harness");
    }

    // --- Semantic Capture Hooks ---

    #[test]
    fn capture_manifest_tracking() {
        init_test("capture_manifest_tracking");
        let mut manifest = CaptureManifest::new();
        manifest.observed("terminal_outcome", "outcome_match");
        manifest.inferred("cancellation.acknowledged", "task_handle.join");
        manifest.unsupported("cancellation.checkpoint_observed");

        assert_eq!(manifest.total_fields(), 3);
        assert_eq!(manifest.unsupported_count(), 1);
        assert!(!manifest.fully_observed());
        assert_eq!(
            manifest.unsupported_fields,
            vec!["cancellation.checkpoint_observed"]
        );
        crate::test_complete!("capture_manifest_tracking");
    }

    #[test]
    fn capture_manifest_fully_observed() {
        init_test("capture_manifest_fully_observed");
        let mut manifest = CaptureManifest::new();
        manifest.observed("outcome", "match");
        manifest.observed("cancel", "hook");
        assert!(manifest.fully_observed());
        crate::test_complete!("capture_manifest_fully_observed");
    }

    #[test]
    fn capture_manifest_empty_is_not_fully_observed() {
        init_test("capture_manifest_empty_is_not_fully_observed");
        let manifest = CaptureManifest::new();
        assert!(!manifest.fully_observed());
        crate::test_complete!("capture_manifest_empty_is_not_fully_observed");
    }

    #[test]
    fn capture_manifest_serde() {
        init_test("capture_manifest_serde");
        let mut manifest = CaptureManifest::new();
        manifest.observed("outcome", "match");
        manifest.unsupported("checkpoint");
        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: CaptureManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_fields(), 2);
        crate::test_complete!("capture_manifest_serde");
    }

    #[test]
    fn capture_manifest_canonicalizes_and_resolves_parent_fields() {
        init_test("capture_manifest_canonicalizes_and_resolves_parent_fields");
        let mut manifest = CaptureManifest::new();
        manifest.unsupported("terminal_outcome");
        manifest.observed("resource_surface.counters.items", "counter");
        manifest.observed("terminal_outcome", "hook");
        manifest.inferred("cancellation", "fallback");

        let fields: Vec<&str> = manifest
            .annotations
            .iter()
            .map(|annotation| annotation.field.as_str())
            .collect();
        assert_eq!(
            fields,
            vec![
                "cancellation",
                "resource_surface.counters.items",
                "terminal_outcome"
            ]
        );
        assert!(manifest.unsupported_fields.is_empty());
        assert_eq!(
            manifest
                .annotation_for_field("semantics.resource_surface.counters.items")
                .unwrap()
                .source,
            "counter"
        );
        assert_eq!(
            manifest
                .describe_field_capture("semantics.terminal_outcome.class")
                .as_deref(),
            Some("observed via hook")
        );
        crate::test_complete!("capture_manifest_canonicalizes_and_resolves_parent_fields");
    }

    #[test]
    fn capture_terminal_from_outcome_ok() {
        init_test("capture_terminal_from_outcome_ok");
        let outcome: crate::types::outcome::Outcome<i32, String> =
            crate::types::outcome::Outcome::Ok(42);
        let t = capture_terminal_outcome(&outcome);
        assert_eq!(t.class, OutcomeClass::Ok);
        assert_eq!(t.severity, OutcomeClass::Ok);
        crate::test_complete!("capture_terminal_from_outcome_ok");
    }

    #[test]
    fn capture_terminal_from_outcome_err() {
        init_test("capture_terminal_from_outcome_err");
        let outcome: crate::types::outcome::Outcome<i32, String> =
            crate::types::outcome::Outcome::Err("network_error".to_string());
        let t = capture_terminal_outcome(&outcome);
        assert_eq!(t.class, OutcomeClass::Err);
        assert_eq!(t.error_class.as_deref(), Some("network_error"));
        crate::test_complete!("capture_terminal_from_outcome_err");
    }

    #[test]
    fn capture_terminal_from_outcome_cancelled() {
        init_test("capture_terminal_from_outcome_cancelled");
        let outcome: crate::types::outcome::Outcome<i32, String> =
            crate::types::outcome::Outcome::Cancelled(crate::types::CancelReason::new(
                crate::types::CancelKind::User,
            ));
        let t = capture_terminal_outcome(&outcome);
        assert_eq!(t.class, OutcomeClass::Cancelled);
        assert!(t.cancel_reason_class.is_some());
        crate::test_complete!("capture_terminal_from_outcome_cancelled");
    }

    #[test]
    fn capture_terminal_from_result_ok_and_err() {
        init_test("capture_terminal_from_result_ok_and_err");
        let ok: Result<i32, String> = Ok(42);
        let err: Result<i32, String> = Err("fail".to_string());
        assert_eq!(
            super::capture_terminal_from_result(&ok).class,
            OutcomeClass::Ok
        );
        assert_eq!(
            super::capture_terminal_from_result(&err).class,
            OutcomeClass::Err
        );
        crate::test_complete!("capture_terminal_from_result_ok_and_err");
    }

    #[test]
    fn capture_obligation_balanced() {
        init_test("capture_obligation_balanced");
        let b = capture_obligation_balance(10, 8, 2);
        assert!(b.balanced);
        assert_eq!(b.leaked, 0);
        assert_eq!(b.unresolved, 0);
        crate::test_complete!("capture_obligation_balanced");
    }

    #[test]
    fn capture_obligation_leaked() {
        init_test("capture_obligation_leaked");
        let b = capture_obligation_balance(10, 5, 2);
        assert!(!b.balanced);
        assert_eq!(b.leaked, 3);
        crate::test_complete!("capture_obligation_leaked");
    }

    #[test]
    fn capture_region_close_quiescent() {
        init_test("capture_region_close_quiescent");
        let r = capture_region_close(true, true);
        assert!(r.quiescent);
        assert!(r.close_completed);
        assert_eq!(r.root_state, RegionState::Closed);
        assert_eq!(r.live_children, 0);
        crate::test_complete!("capture_region_close_quiescent");
    }

    #[test]
    fn capture_region_close_not_quiescent() {
        init_test("capture_region_close_not_quiescent");
        let r = capture_region_close(false, true);
        assert!(!r.quiescent);
        assert!(!r.close_completed);
        assert_eq!(r.root_state, RegionState::Draining);
        assert_eq!(r.live_children, 1);
        assert_eq!(r.finalizers_pending, 0);
        crate::test_complete!("capture_region_close_not_quiescent");
    }

    #[test]
    fn capture_region_close_finalizing() {
        init_test("capture_region_close_finalizing");
        let r = capture_region_close(true, false);
        assert!(!r.quiescent);
        assert!(!r.close_completed);
        assert_eq!(r.root_state, RegionState::Finalizing);
        assert_eq!(r.live_children, 0);
        assert_eq!(r.finalizers_pending, 1);
        crate::test_complete!("capture_region_close_finalizing");
    }

    #[test]
    fn capture_loser_drain_not_applicable() {
        init_test("capture_loser_drain_not_applicable");
        let d = capture_loser_drain(&[]);
        assert!(!d.applicable);
        assert_eq!(d.status, DrainStatus::NotApplicable);
        crate::test_complete!("capture_loser_drain_not_applicable");
    }

    #[test]
    fn capture_loser_drain_all_drained() {
        init_test("capture_loser_drain_all_drained");
        let d = capture_loser_drain(&[true, true, true]);
        assert!(d.applicable);
        assert_eq!(d.status, DrainStatus::Complete);
        assert_eq!(d.expected_losers, 3);
        assert_eq!(d.drained_losers, 3);
        crate::test_complete!("capture_loser_drain_all_drained");
    }

    #[test]
    fn capture_loser_drain_partial() {
        init_test("capture_loser_drain_partial");
        let d = capture_loser_drain(&[true, false, true]);
        assert_eq!(d.status, DrainStatus::Incomplete);
        assert_eq!(d.drained_losers, 2);
        crate::test_complete!("capture_loser_drain_partial");
    }

    #[test]
    fn capture_cancellation_not_cancelled() {
        init_test("capture_cancellation_not_cancelled");
        let c = capture_cancellation(false, false, false, false, None);
        assert_eq!(c.terminal_phase, CancelTerminalPhase::NotCancelled);
        assert!(!c.requested);
        crate::test_complete!("capture_cancellation_not_cancelled");
    }

    #[test]
    fn capture_cancellation_completed() {
        init_test("capture_cancellation_completed");
        let c = capture_cancellation(true, true, true, true, Some(true));
        assert_eq!(c.terminal_phase, CancelTerminalPhase::Completed);
        assert!(c.requested);
        assert!(c.acknowledged);
        assert!(c.cleanup_completed);
        assert!(c.finalization_completed);
        assert_eq!(c.checkpoint_observed, Some(true));
        crate::test_complete!("capture_cancellation_completed");
    }

    #[test]
    fn capture_cancellation_in_progress() {
        init_test("capture_cancellation_in_progress");
        let c = capture_cancellation(true, true, false, false, None);
        assert_eq!(c.terminal_phase, CancelTerminalPhase::Cancelling);
        crate::test_complete!("capture_cancellation_in_progress");
    }

    #[test]
    fn capture_cancellation_finalizing() {
        init_test("capture_cancellation_finalizing");
        let c = capture_cancellation(true, true, true, false, None);
        assert_eq!(c.terminal_phase, CancelTerminalPhase::Finalizing);
        crate::test_complete!("capture_cancellation_finalizing");
    }

    // --- Lab Normalizer ---

    fn make_passing_oracle_report() -> crate::lab::oracle::OracleReport {
        crate::lab::oracle::OracleReport {
            entries: vec![],
            total: 0,
            passed: 0,
            failed: 0,
            check_time_nanos: 0,
        }
    }

    fn make_passing_lab_report(seed: u64) -> crate::lab::runtime::LabRunReport {
        crate::lab::runtime::LabRunReport {
            seed,
            steps_delta: 100,
            steps_total: 100,
            quiescent: true,
            now_nanos: 0,
            trace_len: 10,
            trace_fingerprint: 0xABCD,
            trace_certificate: crate::lab::runtime::LabTraceCertificateSummary {
                event_hash: 0x1234,
                event_count: 10,
                schedule_hash: 0x5678,
            },
            oracle_report: make_passing_oracle_report(),
            invariant_violations: vec![],
            temporal_invariant_failures: vec![],
            temporal_counterexample_prefix_len: None,
            refinement_firewall_rule_id: None,
            refinement_firewall_event_index: None,
            refinement_firewall_event_seq: None,
            refinement_counterexample_prefix_len: None,
            refinement_firewall_skipped_due_to_trace_truncation: false,
        }
    }

    fn make_golden_live_result(identity: &DualRunScenarioIdentity) -> LiveRunResult {
        run_live_adapter(identity, |_, witness| {
            witness.set_outcome(TerminalOutcome::ok());
            witness.set_loser_drain(LoserDrainRecord::complete(2));
            witness.record_counter("items", 5);
            witness.record_counter_with_tolerance("bytes", 128, CounterTolerance::AtLeast);
            witness.note_nondeterminism("scheduler jitter");
        })
    }

    #[test]
    fn normalize_lab_report_happy_path() {
        init_test("normalize_lab_report_happy_path");
        let report = make_passing_lab_report(42);
        let (sem, manifest) = normalize_lab_report(&report, "test.surface");
        assert_eq!(sem.terminal_outcome.class, OutcomeClass::Ok);
        assert!(sem.region_close.quiescent);
        assert!(sem.obligation_balance.balanced);
        assert!(manifest.total_fields() > 0);
        crate::test_complete!("normalize_lab_report_happy_path");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn normalize_lab_report_matches_golden_record() {
        init_test("normalize_lab_report_matches_golden_record");
        let identity = DualRunScenarioIdentity::phase1(
            "golden.lab",
            "test.surface",
            "v1",
            "Golden lab normalization",
            42,
        );
        let report = make_passing_lab_report(42);
        let (semantics, manifest) = normalize_lab_report(&report, "test.surface");
        let observable = normalize_lab_observable(&identity, &report);

        assert_eq!(observable.semantics, semantics);
        assert_eq!(
            serde_json::to_value(&manifest).unwrap(),
            serde_json::json!({
                "annotations": [
                    {
                        "field": "cancellation",
                        "observability": "inferred",
                        "source": "no_oracle_entry",
                    },
                    {
                        "field": "loser_drain",
                        "observability": "inferred",
                        "source": "no_oracle_entry",
                    },
                    {
                        "field": "obligation_balance",
                        "observability": "observed",
                        "source": "oracle.obligation_leak + invariants",
                    },
                    {
                        "field": "region_close.quiescent",
                        "observability": "observed",
                        "source": "LabRunReport.quiescent",
                    },
                    {
                        "field": "terminal_outcome",
                        "observability": "observed",
                        "source": "oracle_report.all_passed",
                    }
                ],
                "unsupported_fields": [],
            })
        );
        assert_eq!(
            serde_json::to_value(&observable).unwrap(),
            serde_json::json!({
                "schema_version": NORMALIZED_OBSERVABLE_SCHEMA_VERSION,
                "scenario_id": "golden.lab",
                "surface_id": "test.surface",
                "surface_contract_version": "v1",
                "runtime_kind": "lab",
                "semantics": {
                    "terminal_outcome": {
                        "class": "ok",
                        "severity": "ok",
                    },
                    "cancellation": {
                        "requested": false,
                        "acknowledged": false,
                        "cleanup_completed": false,
                        "finalization_completed": false,
                        "terminal_phase": "not_cancelled",
                    },
                    "loser_drain": {
                        "applicable": false,
                        "expected_losers": 0,
                        "drained_losers": 0,
                        "status": "not_applicable",
                    },
                    "region_close": {
                        "root_state": "closed",
                        "quiescent": true,
                        "live_children": 0,
                        "finalizers_pending": 0,
                        "close_completed": true,
                    },
                    "obligation_balance": {
                        "reserved": 0,
                        "committed": 0,
                        "aborted": 0,
                        "leaked": 0,
                        "unresolved": 0,
                        "balanced": true,
                    },
                    "resource_surface": {
                        "contract_scope": "test.surface",
                        "counters": {},
                        "tolerances": {},
                    },
                },
                "provenance": {
                    "family": {
                        "id": "golden.lab",
                        "surface_id": "test.surface",
                        "surface_contract_version": "v1",
                    },
                    "instance": {
                        "family_id": "golden.lab",
                        "effective_seed": 42,
                        "runtime_kind": "lab",
                        "run_index": 0,
                    },
                    "seed_plan": {
                        "canonical_seed": 42,
                        "seed_lineage_id": "golden.lab",
                        "lab_seed_mode": "inherit",
                        "live_seed_mode": "inherit",
                        "replay_policy": "single_seed",
                    },
                    "effective_seed": 42,
                    "effective_entropy_seed": derive_component_seed(42, "entropy"),
                    "trace_fingerprint": 43981,
                    "schedule_hash": 22136,
                    "event_hash": 4660,
                    "event_count": 10,
                    "steps_total": 100,
                },
            })
        );
        crate::test_complete!("normalize_lab_report_matches_golden_record");
    }

    #[test]
    fn normalize_lab_report_invariant_violation() {
        init_test("normalize_lab_report_invariant_violation");
        let mut report = make_passing_lab_report(42);
        report.invariant_violations = vec!["obligation leak detected".to_string()];
        let (sem, _) = normalize_lab_report(&report, "test");
        assert_eq!(sem.terminal_outcome.class, OutcomeClass::Err);
        assert!(!sem.obligation_balance.balanced);
        crate::test_complete!("normalize_lab_report_invariant_violation");
    }

    #[test]
    fn normalize_lab_report_not_quiescent() {
        init_test("normalize_lab_report_not_quiescent");
        let mut report = make_passing_lab_report(42);
        report.quiescent = false;
        let (sem, _) = normalize_lab_report(&report, "test");
        assert!(!sem.region_close.quiescent);
        assert!(!sem.region_close.close_completed);
        assert_eq!(sem.region_close.root_state, RegionState::Closing);
        crate::test_complete!("normalize_lab_report_not_quiescent");
    }

    #[test]
    fn normalize_lab_observable_preserves_provenance() {
        init_test("normalize_lab_observable_preserves_provenance");
        let ident = DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 42);
        let report = make_passing_lab_report(42);
        let obs = normalize_lab_observable(&ident, &report);
        assert_eq!(obs.runtime_kind, RuntimeKind::Lab);
        assert_eq!(obs.provenance.trace_fingerprint, Some(0xABCD));
        assert_eq!(obs.provenance.event_hash, Some(0x1234));
        assert_eq!(obs.provenance.steps_total, Some(100));
        crate::test_complete!("normalize_lab_observable_preserves_provenance");
    }

    #[test]
    fn normalize_live_observable_from_result() {
        init_test("normalize_live_observable_from_result");
        let ident = DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 42);
        let live_result = run_live_adapter(&ident, |_, witness| {
            witness.set_outcome(TerminalOutcome::ok());
            witness.record_counter("items", 5);
            witness.note_nondeterminism("thread scheduling");
        });
        let obs = normalize_live_observable(&ident, &live_result);
        assert_eq!(obs.runtime_kind, RuntimeKind::Live);
        assert_eq!(obs.semantics.terminal_outcome.class, OutcomeClass::Ok);
        assert_eq!(obs.semantics.resource_surface.counters["items"], 5);
        assert_eq!(obs.provenance.nondeterminism_notes, ["thread scheduling"]);
        crate::test_complete!("normalize_live_observable_from_result");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn normalize_live_observable_matches_golden_record_and_manifest() {
        init_test("normalize_live_observable_matches_golden_record_and_manifest");
        let identity = DualRunScenarioIdentity::phase1(
            "golden.live",
            "test.surface",
            "v1",
            "Golden live normalization",
            42,
        );
        let live_result = make_golden_live_result(&identity);
        let observable = normalize_live_observable(&identity, &live_result);

        assert_eq!(
            serde_json::to_value(&live_result.metadata.capture_manifest).unwrap(),
            serde_json::json!({
                "annotations": [
                    {
                        "field": "cancellation",
                        "observability": "inferred",
                        "source": "run_live_adapter.default_no_cancellation",
                    },
                    {
                        "field": "cancellation.checkpoint_observed",
                        "observability": "unsupported",
                        "source": "default",
                    },
                    {
                        "field": "loser_drain",
                        "observability": "observed",
                        "source": "witness.set_loser_drain",
                    },
                    {
                        "field": "obligation_balance",
                        "observability": "inferred",
                        "source": "run_live_adapter.default_balanced_obligations",
                    },
                    {
                        "field": "region_close",
                        "observability": "inferred",
                        "source": "run_live_adapter.default_quiescent",
                    },
                    {
                        "field": "resource_surface.contract_scope",
                        "observability": "observed",
                        "source": "scenario_identity.surface_id",
                    },
                    {
                        "field": "resource_surface.counters.bytes",
                        "observability": "observed",
                        "source": "witness.record_counter_with_tolerance",
                    },
                    {
                        "field": "resource_surface.counters.items",
                        "observability": "observed",
                        "source": "witness.record_counter",
                    },
                    {
                        "field": "resource_surface.tolerances.bytes",
                        "observability": "observed",
                        "source": "witness.record_counter_with_tolerance",
                    },
                    {
                        "field": "resource_surface.tolerances.items",
                        "observability": "observed",
                        "source": "witness.record_counter",
                    },
                    {
                        "field": "terminal_outcome",
                        "observability": "observed",
                        "source": "witness.set_outcome",
                    }
                ],
                "unsupported_fields": ["cancellation.checkpoint_observed"],
            })
        );
        assert_eq!(
            serde_json::to_value(&observable).unwrap(),
            serde_json::json!({
                "schema_version": NORMALIZED_OBSERVABLE_SCHEMA_VERSION,
                "scenario_id": "golden.live",
                "surface_id": "test.surface",
                "surface_contract_version": "v1",
                "runtime_kind": "live",
                "semantics": {
                    "terminal_outcome": {
                        "class": "ok",
                        "severity": "ok",
                    },
                    "cancellation": {
                        "requested": false,
                        "acknowledged": false,
                        "cleanup_completed": false,
                        "finalization_completed": false,
                        "terminal_phase": "not_cancelled",
                    },
                    "loser_drain": {
                        "applicable": true,
                        "expected_losers": 2,
                        "drained_losers": 2,
                        "status": "complete",
                    },
                    "region_close": {
                        "root_state": "closed",
                        "quiescent": true,
                        "live_children": 0,
                        "finalizers_pending": 0,
                        "close_completed": true,
                    },
                    "obligation_balance": {
                        "reserved": 0,
                        "committed": 0,
                        "aborted": 0,
                        "leaked": 0,
                        "unresolved": 0,
                        "balanced": true,
                    },
                    "resource_surface": {
                        "contract_scope": "test.surface",
                        "counters": {
                            "bytes": 128,
                            "items": 5,
                        },
                        "tolerances": {
                            "bytes": "at_least",
                            "items": "exact",
                        },
                    },
                },
                "provenance": {
                    "family": {
                        "id": "golden.live",
                        "surface_id": "test.surface",
                        "surface_contract_version": "v1",
                    },
                    "instance": {
                        "family_id": "golden.live",
                        "effective_seed": 42,
                        "runtime_kind": "live",
                        "run_index": 0,
                    },
                    "seed_plan": {
                        "canonical_seed": 42,
                        "seed_lineage_id": "golden.live",
                        "lab_seed_mode": "inherit",
                        "live_seed_mode": "inherit",
                        "replay_policy": "single_seed",
                    },
                    "effective_seed": 42,
                    "effective_entropy_seed": derive_component_seed(42, "entropy"),
                    "nondeterminism_notes": ["scheduler jitter"],
                },
            })
        );
        crate::test_complete!("normalize_live_observable_matches_golden_record_and_manifest");
    }

    #[test]
    fn normalize_and_compare_lab_vs_live() {
        init_test("normalize_and_compare_lab_vs_live");
        let ident = DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 42);

        // Lab side
        let report = make_passing_lab_report(42);
        let lab_obs = normalize_lab_observable(&ident, &report);

        // Live side
        let live_result = run_live_adapter(&ident, |_, _| {});
        let live_obs = normalize_live_observable(&ident, &live_result);

        // Compare
        let lineage = ident.seed_lineage();
        let verdict = compare_observables(&lab_obs, &live_obs, lineage);
        // Both should have ok outcomes and quiescent regions
        assert!(verdict.passed, "Verdict: {}", verdict.summary());
        crate::test_complete!("normalize_and_compare_lab_vs_live");
    }

    #[test]
    fn mismatch_summary_with_manifests_includes_capture_sources() {
        init_test("mismatch_summary_with_manifests_includes_capture_sources");
        let identity = DualRunScenarioIdentity::phase1(
            "capture.summary",
            "test.surface",
            "v1",
            "Mismatch summaries should include capture provenance",
            42,
        );

        let mut report = make_passing_lab_report(42);
        report.invariant_violations = vec!["obligation leak detected".to_string()];
        let (lab_semantics, lab_manifest) = normalize_lab_report(&report, "test.surface");
        let lab = NormalizedObservable::new(
            &identity,
            RuntimeKind::Lab,
            lab_semantics,
            identity.lab_replay_metadata(),
        );

        let live_result = run_live_adapter(&identity, |_, witness| {
            witness.set_outcome(TerminalOutcome::ok());
        });
        let live = normalize_live_observable(&identity, &live_result);

        let verdict = compare_observables(&lab, &live, identity.seed_lineage());
        assert!(!verdict.passed);

        let summary = verdict.summary_with_manifests(
            Some(&lab_manifest),
            Some(&live_result.metadata.capture_manifest),
        );
        assert!(summary.contains("semantics.terminal_outcome.class"));
        assert!(summary.contains("lab_capture=observed via invariant_violations"));
        assert!(summary.contains("live_capture=observed via witness.set_outcome"));
        crate::test_complete!("mismatch_summary_with_manifests_includes_capture_sources");
    }

    // --- Fuzz-to-Scenario Promotion ---

    fn make_test_fuzz_finding(seed: u64) -> crate::lab::fuzz::FuzzFinding {
        crate::lab::fuzz::FuzzFinding {
            seed,
            entropy_seed: 0xFACE,
            steps: 500,
            violations: vec![],
            certificate_hash: 0xABCD,
            trace_fingerprint: 0x1234,
            minimized_seed: Some(seed.wrapping_add(1)),
        }
    }

    #[test]
    fn promote_fuzz_finding_basic() {
        init_test("promote_fuzz_finding_basic");
        let finding = make_test_fuzz_finding(0xDEAD);
        let promoted = promote_fuzz_finding(&finding, "cancellation", "v1");
        assert!(promoted.identity.scenario_id.contains("fuzz"));
        assert!(promoted.identity.scenario_id.contains("cancellation"));
        assert_eq!(promoted.replay_seed, 0xDEAD + 1); // minimized
        assert_eq!(promoted.original_seed, 0xDEAD);
        assert_eq!(promoted.identity.seed_plan.canonical_seed, 0xDEAD + 1);
        assert_eq!(
            promoted.identity.seed_plan.entropy_seed_override,
            Some(0xFACE)
        );
        assert_eq!(promoted.identity.phase, Phase::Phase1);
        assert!(promoted.identity.metadata.contains_key("promoted_from"));
        crate::test_complete!("promote_fuzz_finding_basic");
    }

    #[test]
    fn promote_fuzz_finding_no_minimized_seed() {
        init_test("promote_fuzz_finding_no_minimized_seed");
        let mut finding = make_test_fuzz_finding(0xBEEF);
        finding.minimized_seed = None;
        let promoted = promote_fuzz_finding(&finding, "obligation", "v1");
        assert_eq!(promoted.replay_seed, 0xBEEF); // falls back to original
        crate::test_complete!("promote_fuzz_finding_no_minimized_seed");
    }

    #[test]
    fn promote_fuzz_finding_stabilizes_violation_categories_and_metadata() {
        init_test("promote_fuzz_finding_stabilizes_violation_categories_and_metadata");
        let mut finding = make_test_fuzz_finding(0xD00D);
        finding.violations = vec![
            crate::lab::runtime::InvariantViolation::QuiescenceViolation,
            crate::lab::runtime::InvariantViolation::Futurelock {
                task: crate::types::TaskId::new_for_test(1, 0),
                region: crate::types::RegionId::new_for_test(1, 0),
                idle_steps: 1,
                held: Vec::new(),
                last_checkpoint_message: None,
            },
            crate::lab::runtime::InvariantViolation::QuiescenceViolation,
        ];

        let promoted = promote_fuzz_finding(&finding, "cancellation", "v1");
        assert_eq!(
            promoted.violation_categories,
            vec!["futurelock", "quiescence_violation"]
        );
        assert!(promoted.identity.scenario_id.contains("futurelock"));
        assert_eq!(
            promoted.identity.metadata.get("violation_categories"),
            Some(&"futurelock,quiescence_violation".to_string())
        );
        assert_eq!(
            promoted.identity.metadata.get("certificate_hash"),
            Some(&"0xABCD".to_string())
        );
        crate::test_complete!("promote_fuzz_finding_stabilizes_violation_categories_and_metadata");
    }

    #[test]
    fn promote_fuzz_finding_repro_command() {
        init_test("promote_fuzz_finding_repro_command");
        let finding = make_test_fuzz_finding(42);
        let promoted = promote_fuzz_finding(&finding, "drain", "v1");
        let cmd = promoted.repro_command();
        assert!(cmd.contains("rch exec -- env ASUPERSYNC_SEED="));
        assert!(cmd.contains("ASUPERSYNC_SEED"));
        assert!(cmd.contains("cargo test"));
        crate::test_complete!("promote_fuzz_finding_repro_command");
    }

    #[test]
    fn promote_fuzz_finding_display() {
        init_test("promote_fuzz_finding_display");
        let finding = make_test_fuzz_finding(42);
        let promoted = promote_fuzz_finding(&finding, "test", "v1");
        let s = format!("{promoted}");
        assert!(s.contains("PromotedFuzz"));
        crate::test_complete!("promote_fuzz_finding_display");
    }

    #[test]
    fn promote_fuzz_finding_serde_roundtrip() {
        init_test("promote_fuzz_finding_serde_roundtrip");
        let finding = make_test_fuzz_finding(0xCAFE);
        let promoted = promote_fuzz_finding(&finding, "test", "v1")
            .with_source_artifact_path("/tmp/fuzz/report.json");
        let json = serde_json::to_string_pretty(&promoted).unwrap();
        let parsed: PromotedFuzzScenario = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.replay_seed, promoted.replay_seed);
        assert_eq!(parsed.original_seed, 0xCAFE);
        assert_eq!(
            parsed.source_artifact_path.as_deref(),
            Some("/tmp/fuzz/report.json")
        );
        crate::test_complete!("promote_fuzz_finding_serde_roundtrip");
    }

    #[test]
    fn promoted_fuzz_scenario_replay_metadata_includes_artifact_and_repro() {
        init_test("promoted_fuzz_scenario_replay_metadata_includes_artifact_and_repro");
        let finding = make_test_fuzz_finding(0xCAFE);
        let promoted = promote_fuzz_finding(&finding, "test.surface", "v1")
            .with_source_artifact_path("/tmp/fuzz/report.json");

        let metadata = promoted.lab_replay_metadata();
        assert_eq!(metadata.trace_fingerprint, Some(promoted.trace_fingerprint));
        assert_eq!(
            metadata.artifact_path.as_deref(),
            Some("/tmp/fuzz/report.json")
        );
        assert_eq!(
            metadata.repro_command.as_deref(),
            Some(promoted.repro_command().as_str())
        );
        crate::test_complete!("promoted_fuzz_scenario_replay_metadata_includes_artifact_and_repro");
    }

    #[test]
    fn promote_regression_case_basic() {
        init_test("promote_regression_case_basic");
        let case = crate::lab::fuzz::FuzzRegressionCase {
            seed: 0xDEAD,
            replay_seed: 0xBEEF,
            entropy_seed: 0xCAFE,
            certificate_hash: 0x1111,
            trace_fingerprint: 0x2222,
            violation_categories: vec!["obligation_leak".to_string()],
        };
        let promoted = promote_regression_case(&case, "obligation", "v1");
        assert!(promoted.identity.scenario_id.contains("regression"));
        assert_eq!(promoted.replay_seed, 0xBEEF);
        assert_eq!(
            promoted.identity.seed_plan.entropy_seed_override,
            Some(0xCAFE)
        );
        assert_eq!(promoted.violation_categories, vec!["obligation_leak"]);
        crate::test_complete!("promote_regression_case_basic");
    }

    #[test]
    fn promote_regression_corpus_preserves_order() {
        init_test("promote_regression_corpus_preserves_order");
        let corpus = crate::lab::fuzz::FuzzRegressionCorpus {
            schema_version: 1,
            base_seed: 42,
            entropy_seed: 0x777,
            iterations: 1000,
            cases: vec![
                crate::lab::fuzz::FuzzRegressionCase {
                    seed: 1,
                    replay_seed: 10,
                    entropy_seed: 0x777,
                    certificate_hash: 0,
                    trace_fingerprint: 0,
                    violation_categories: vec!["a".to_string()],
                },
                crate::lab::fuzz::FuzzRegressionCase {
                    seed: 2,
                    replay_seed: 20,
                    entropy_seed: 0x777,
                    certificate_hash: 0,
                    trace_fingerprint: 0,
                    violation_categories: vec!["b".to_string()],
                },
            ],
        };
        let promoted = promote_regression_corpus(&corpus, "test", "v1");
        assert_eq!(promoted.len(), 2);
        assert_eq!(promoted[0].replay_seed, 10);
        assert_eq!(promoted[1].replay_seed, 20);
        assert_eq!(promoted[0].campaign_base_seed, Some(42));
        assert_eq!(promoted[0].campaign_iteration, Some(0));
        assert_eq!(promoted[1].campaign_iteration, Some(1));
        assert_eq!(
            promoted[0].identity.seed_plan.entropy_seed_override,
            Some(0x777)
        );
        assert_eq!(
            promoted[0].identity.metadata.get("campaign_entropy_seed"),
            Some(&"0x777".to_string())
        );
        crate::test_complete!("promote_regression_corpus_preserves_order");
    }

    #[test]
    fn promoted_fuzz_scenario_runs_through_harness() {
        init_test("promoted_fuzz_scenario_runs_through_harness");
        let finding = make_test_fuzz_finding(42);
        let promoted = promote_fuzz_finding(&finding, "test.surface", "v1");

        // Use the promoted identity in a DualRunHarness
        let result = DualRunHarness::from_identity(promoted.identity)
            .lab(|_config| make_happy_semantics())
            .live(|_seed, _entropy| make_happy_semantics())
            .run();

        assert!(result.passed());
        crate::test_complete!("promoted_fuzz_scenario_runs_through_harness");
    }

    #[test]
    fn promoted_regression_corpus_case_runs_through_harness_with_campaign_metadata() {
        init_test("promoted_regression_corpus_case_runs_through_harness_with_campaign_metadata");
        let corpus = crate::lab::fuzz::FuzzRegressionCorpus {
            schema_version: 1,
            base_seed: 0x2A,
            entropy_seed: 0x2B,
            iterations: 3,
            cases: vec![crate::lab::fuzz::FuzzRegressionCase {
                seed: 0x10,
                replay_seed: 0x11,
                entropy_seed: 0x2B,
                certificate_hash: 0x2222,
                trace_fingerprint: 0x3333,
                violation_categories: vec!["obligation_leak".to_string()],
            }],
        };
        let promoted = promote_regression_corpus(&corpus, "test.surface", "v1");
        let promoted = promoted[0]
            .clone()
            .with_source_artifact_path("/tmp/fuzz/corpus.json");

        assert_eq!(promoted.campaign_base_seed, Some(0x2A));
        assert_eq!(promoted.campaign_iteration, Some(0));
        assert_eq!(
            promoted.identity.metadata.get("campaign_base_seed"),
            Some(&"0x2A".to_string())
        );
        assert_eq!(
            promoted.identity.metadata.get("campaign_iteration"),
            Some(&"0".to_string())
        );

        let metadata = promoted.lab_replay_metadata();
        assert_eq!(metadata.trace_fingerprint, Some(0x3333));
        assert_eq!(
            metadata.artifact_path.as_deref(),
            Some("/tmp/fuzz/corpus.json")
        );

        let result = DualRunHarness::from_identity(promoted.identity)
            .lab(|_config| make_happy_semantics())
            .live(|_seed, _entropy| make_happy_semantics())
            .run();
        assert!(result.passed());
        crate::test_complete!(
            "promoted_regression_corpus_case_runs_through_harness_with_campaign_metadata"
        );
    }

    fn make_test_exploration_report() -> crate::lab::explorer::ExplorationReport {
        use crate::lab::explorer::{
            CoverageMetrics, RunResult, SaturationMetrics, ViolationReport,
        };
        use crate::lab::runtime::InvariantViolation;

        crate::lab::explorer::ExplorationReport {
            total_runs: 3,
            unique_classes: 2,
            violations: vec![ViolationReport {
                seed: 0x20,
                steps: 42,
                violations: vec![InvariantViolation::QuiescenceViolation],
                fingerprint: 0xAAAA,
            }],
            coverage: CoverageMetrics {
                equivalence_classes: 2,
                total_runs: 3,
                new_class_discoveries: 2,
                class_run_counts: BTreeMap::from([(0xAAAA, 2), (0xBBBB, 1)]),
                novelty_histogram: BTreeMap::from([(0, 1), (1, 2)]),
                saturation: SaturationMetrics {
                    window: 10,
                    saturated: false,
                    existing_class_hits: 1,
                    runs_since_last_new_class: Some(1),
                },
            },
            top_unexplored: Vec::new(),
            runs: vec![
                RunResult {
                    seed: 0x10,
                    steps: 10,
                    fingerprint: 0xAAAA,
                    is_new_class: true,
                    violations: Vec::new(),
                    certificate_hash: 0x100,
                },
                RunResult {
                    seed: 0x20,
                    steps: 42,
                    fingerprint: 0xAAAA,
                    is_new_class: false,
                    violations: vec![InvariantViolation::QuiescenceViolation],
                    certificate_hash: 0x200,
                },
                RunResult {
                    seed: 0x30,
                    steps: 11,
                    fingerprint: 0xBBBB,
                    is_new_class: true,
                    violations: Vec::new(),
                    certificate_hash: 0x300,
                },
            ],
        }
    }

    #[test]
    fn promote_exploration_report_prefers_lowest_violation_seed_and_preserves_lineage() {
        init_test("promote_exploration_report_prefers_lowest_violation_seed_and_preserves_lineage");
        let report = make_test_exploration_report();
        let promoted = promote_exploration_report(&report, "schedule.surface", "v1");
        assert_eq!(promoted.len(), 2);

        let promoted_class = promoted
            .iter()
            .find(|scenario| scenario.trace_fingerprint == 0xAAAA)
            .expect("class 0xAAAA should be promoted");
        assert_eq!(promoted_class.replay_seed, 0x20);
        assert_eq!(promoted_class.original_seeds, vec![0x10, 0x20]);
        assert_eq!(promoted_class.violation_seeds, vec![0x20]);
        assert_eq!(
            promoted_class.supporting_schedule_hashes,
            vec![0x100, 0x200]
        );
        assert!(
            promoted_class
                .violation_summaries
                .iter()
                .any(|summary| summary.contains("region closed without quiescence"))
        );
        assert_eq!(
            promoted_class.identity.metadata.get("promoted_from"),
            Some(&"exploration_report".to_owned())
        );
        assert_eq!(
            promoted_class
                .identity
                .metadata
                .get("representative_reason"),
            Some(&"lowest_violation_seed".to_owned())
        );
        crate::test_complete!(
            "promote_exploration_report_prefers_lowest_violation_seed_and_preserves_lineage"
        );
    }

    #[test]
    fn promoted_exploration_scenario_replay_metadata_includes_artifact_and_repro() {
        init_test("promoted_exploration_scenario_replay_metadata_includes_artifact_and_repro");
        let report = make_test_exploration_report();
        let promoted = promote_exploration_report(&report, "schedule.surface", "v1");
        let promoted = promoted[0]
            .clone()
            .with_source_artifact_path("/tmp/dpor/report.json");

        let metadata = promoted.lab_replay_metadata();
        assert_eq!(metadata.trace_fingerprint, Some(promoted.trace_fingerprint));
        assert_eq!(
            metadata.schedule_hash,
            Some(promoted.representative_schedule_hash)
        );
        assert_eq!(
            metadata.artifact_path.as_deref(),
            Some("/tmp/dpor/report.json")
        );
        assert_eq!(
            metadata.repro_command.as_deref(),
            Some(promoted.repro_command().as_str())
        );
        crate::test_complete!(
            "promoted_exploration_scenario_replay_metadata_includes_artifact_and_repro"
        );
    }

    #[test]
    fn promote_exploration_report_serde_roundtrip() {
        init_test("promote_exploration_report_serde_roundtrip");
        let report = make_test_exploration_report();
        let promoted = promote_exploration_report(&report, "schedule.surface", "v1");
        let json = serde_json::to_string_pretty(&promoted).unwrap();
        let parsed: Vec<PromotedExplorationScenario> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), promoted.len());
        assert_eq!(parsed[0].trace_fingerprint, promoted[0].trace_fingerprint);
        crate::test_complete!("promote_exploration_report_serde_roundtrip");
    }
