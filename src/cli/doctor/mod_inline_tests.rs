    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use tempfile::tempdir;

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent directories");
        }
        fs::write(path, content).expect("write file");
    }

    fn scrub_core_diagnostics_fixture(fixture: &CoreDiagnosticsFixture) -> serde_json::Value {
        serde_json::json!({
            "fixture_id": fixture.fixture_id,
            "description": fixture.description,
            "summary": {
                "status": fixture.report.summary.status,
                "overall_outcome": fixture.report.summary.overall_outcome,
                "total_findings": fixture.report.summary.total_findings,
                "critical_findings": fixture.report.summary.critical_findings,
            },
            "findings": fixture.report.findings.iter().map(|finding| {
                serde_json::json!({
                    "finding_id": finding.finding_id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "status": finding.status,
                })
            }).collect::<Vec<_>>(),
            "evidence": fixture.report.evidence.iter().map(|evidence| {
                serde_json::json!({
                    "evidence_id": evidence.evidence_id,
                    "source": evidence.source,
                    "outcome_class": evidence.outcome_class,
                })
            }).collect::<Vec<_>>(),
            "commands": fixture.report.commands.iter().map(|command| {
                serde_json::json!({
                    "command_id": command.command_id,
                    "tool": command.tool,
                    "exit_code": command.exit_code,
                    "outcome_class": command.outcome_class,
                })
            }).collect::<Vec<_>>(),
            "provenance": {
                "run_id": fixture.report.provenance.run_id,
                "scenario_id": fixture.report.provenance.scenario_id,
                "trace_id": fixture.report.provenance.trace_id,
                "seed": fixture.report.provenance.seed,
                "generated_by": fixture.report.provenance.generated_by,
                "generated_at": "<scrubbed>",
            },
        })
    }

    fn scrub_core_diagnostics_health_fixture(
        fixture: &CoreDiagnosticsFixture,
    ) -> serde_json::Value {
        let health_status = if fixture.report.summary.critical_findings > 0
            || fixture.report.summary.status == "failed"
        {
            "critical"
        } else if fixture.report.summary.status == "degraded" {
            "degraded"
        } else {
            "passing"
        };

        serde_json::json!({
            "fixture_id": fixture.fixture_id,
            "report_id": fixture.report.report_id,
            "scenario_id": fixture.report.provenance.scenario_id,
            "health_status": health_status,
            "summary": {
                "status": fixture.report.summary.status,
                "overall_outcome": fixture.report.summary.overall_outcome,
                "total_findings": fixture.report.summary.total_findings,
                "critical_findings": fixture.report.summary.critical_findings,
            },
            "findings": fixture.report.findings.iter().map(|finding| {
                serde_json::json!({
                    "finding_id": finding.finding_id,
                    "severity": finding.severity,
                    "status": finding.status,
                })
            }).collect::<Vec<_>>(),
            "evidence": fixture.report.evidence.iter().map(|evidence| {
                serde_json::json!({
                    "evidence_id": evidence.evidence_id,
                    "source": evidence.source,
                    "outcome_class": evidence.outcome_class,
                })
            }).collect::<Vec<_>>(),
            "commands": fixture.report.commands.iter().map(|command| {
                serde_json::json!({
                    "command_id": command.command_id,
                    "tool": command.tool,
                    "exit_code": command.exit_code,
                    "outcome_class": command.outcome_class,
                })
            }).collect::<Vec<_>>(),
            "provenance": {
                "run_id": fixture.report.provenance.run_id,
                "trace_id": fixture.report.provenance.trace_id,
                "seed": fixture.report.provenance.seed,
                "generated_by": fixture.report.provenance.generated_by,
                "generated_at": "<scrubbed>",
            },
        })
    }

    fn make_single_member_workspace_report(source: &str) -> WorkspaceScanReport {
        let temp = tempdir().expect("temp dir");
        #[allow(deprecated)]
        let root = temp.into_path();
        write_file(
            &root.join("Cargo.toml"),
            r#"[workspace]
members = ["crate_a"]
"#,
        );
        write_file(
            &root.join("crate_a/Cargo.toml"),
            r#"[package]
name = "crate_a"
version = "0.1.0"
edition = "2024"
"#,
        );
        write_file(&root.join("crate_a/src/lib.rs"), source);
        scan_workspace(&root).expect("scan workspace")
    }

    #[test]
    fn scan_workspace_discovers_members_and_surfaces() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();

        write_file(
            &root.join("Cargo.toml"),
            r#"[workspace]
members = ["crate_a", "crate_b"]
"#,
        );
        write_file(
            &root.join("crate_a/Cargo.toml"),
            r#"[package]
name = "crate_a"
version = "0.1.0"
edition = "2024"
"#,
        );
        write_file(
            &root.join("crate_a/src/lib.rs"),
            "use asupersync::Cx;\nuse asupersync::Scope;\nuse asupersync::channel::mpsc;\n",
        );
        write_file(
            &root.join("crate_b/Cargo.toml"),
            r#"[package]
name = "crate_b"
version = "0.1.0"
edition = "2024"
"#,
        );
        write_file(
            &root.join("crate_b/src/lib.rs"),
            "use asupersync::runtime::RuntimeBuilder;\nuse asupersync::lab::LabRuntime;\n",
        );

        let report = scan_workspace(root).expect("scan workspace");
        assert_eq!(report.members.len(), 2);
        assert_eq!(report.members[0].name, "crate_a");
        assert_eq!(report.members[1].name, "crate_b");
        assert_eq!(report.scanner_version, SCANNER_VERSION);
        assert_eq!(report.taxonomy_version, TAXONOMY_VERSION);
        assert!(
            report
                .events
                .iter()
                .any(|event| event.phase == "scan_complete")
        );
        assert!(
            report
                .capability_edges
                .iter()
                .any(|edge| edge.surface == "cx")
        );
        assert!(
            report
                .capability_edges
                .iter()
                .any(|edge| edge.surface == "runtime")
        );
    }

    #[test]
    fn scan_workspace_supports_simple_wildcard_members() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();

        write_file(
            &root.join("Cargo.toml"),
            r#"[workspace]
members = ["crates/*"]
"#,
        );
        write_file(
            &root.join("crates/a/Cargo.toml"),
            r#"[package]
name = "a"
version = "0.1.0"
edition = "2024"
"#,
        );
        write_file(&root.join("crates/a/src/lib.rs"), "use asupersync::Cx;\n");
        write_file(
            &root.join("crates/b/Cargo.toml"),
            r#"[package]
name = "b"
version = "0.1.0"
edition = "2024"
"#,
        );
        write_file(
            &root.join("crates/b/src/lib.rs"),
            "use asupersync::trace::ReplayEvent;\n",
        );

        let report = scan_workspace(root).expect("scan workspace");
        assert_eq!(report.members.len(), 2);
        assert_eq!(report.members[0].name, "a");
        assert_eq!(report.members[1].name, "b");
    }

    #[test]
    fn scan_workspace_reports_missing_member_manifest() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();

        write_file(
            &root.join("Cargo.toml"),
            r#"[workspace]
members = ["missing_member"]
"#,
        );

        let report = scan_workspace(root).expect("scan workspace");
        assert!(report.members.is_empty());
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("missing Cargo.toml"))
        );
        assert!(report.events.iter().any(|event| event.level == "warn"));
    }

    #[test]
    fn scan_workspace_falls_back_to_single_package_root() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();

        write_file(
            &root.join("Cargo.toml"),
            r#"[package]
name = "root_pkg"
version = "0.1.0"
edition = "2024"
"#,
        );
        write_file(
            &root.join("src/lib.rs"),
            "use asupersync::Cx;\nuse asupersync::Budget;\nuse asupersync::Outcome;\n",
        );

        let report = scan_workspace(root).expect("scan workspace");
        assert_eq!(report.members.len(), 1);
        assert_eq!(report.members[0].name, "root_pkg");
        assert!(
            report.members[0]
                .capability_surfaces
                .iter()
                .any(|surface| surface == "cx")
        );
    }

    #[test]
    fn scan_workspace_warns_on_unterminated_workspace_array() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();

        write_file(
            &root.join("Cargo.toml"),
            r#"[workspace]
members = ["crate_a"
"#,
        );
        write_file(
            &root.join("crate_a/Cargo.toml"),
            r#"[package]
name = "crate_a"
version = "0.1.0"
edition = "2024"
"#,
        );
        write_file(&root.join("crate_a/src/lib.rs"), "use asupersync::Cx;\n");

        let report = scan_workspace(root).expect("scan workspace");
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("unterminated workspace array"))
        );
    }

    #[test]
    fn scan_workspace_warns_on_malformed_package_name() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();

        write_file(
            &root.join("Cargo.toml"),
            r#"[workspace]
members = ["crate_a"]
"#,
        );
        write_file(
            &root.join("crate_a/Cargo.toml"),
            r#"[package]
name = crate_a
version = "0.1.0"
edition = "2024"
"#,
        );
        write_file(&root.join("crate_a/src/lib.rs"), "use asupersync::Cx;\n");

        let report = scan_workspace(root).expect("scan workspace");
        assert_eq!(report.members[0].name, "crate_a");
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("malformed package name"))
        );
    }

    #[test]
    fn analyze_workspace_invariants_flags_missing_cancel_and_obligation_markers() {
        let report =
            make_single_member_workspace_report("use asupersync::Cx;\nuse asupersync::Scope;\n");
        let analysis = analyze_workspace_invariants(&report);

        assert_eq!(analysis.analyzer_version, INVARIANT_ANALYZER_VERSION);
        assert_eq!(analysis.member_count, 1);
        assert_eq!(analysis.finding_count, analysis.findings.len());

        let finding_rule_ids = analysis
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<BTreeSet<_>>();
        assert!(finding_rule_ids.contains("cancel_phase_surface"));
        assert!(finding_rule_ids.contains("obligation_surface"));
        assert!(!finding_rule_ids.contains("scan_lifecycle_events"));

        let lifecycle_trace = analysis
            .rule_traces
            .iter()
            .find(|trace| trace.rule_id == "scan_lifecycle_events")
            .expect("lifecycle trace");
        assert_eq!(lifecycle_trace.outcome, "pass");
    }

    #[test]
    fn analyze_workspace_invariants_flags_missing_scan_complete_event() {
        let report = make_single_member_workspace_report(
            "use asupersync::Cx;\nuse asupersync::Scope;\nuse asupersync::cancel::CancelReason;\nuse asupersync::obligation::Obligation;\n",
        );
        let mut broken = report;
        broken.events.retain(|event| event.phase != "scan_complete");

        let analysis = analyze_workspace_invariants(&broken);
        let finding = analysis
            .findings
            .iter()
            .find(|candidate| candidate.rule_id == "scan_lifecycle_events")
            .expect("lifecycle finding");
        assert_eq!(finding.severity, "error");
        assert!(
            finding
                .evidence
                .iter()
                .any(|line| line.contains("scan_complete"))
        );
    }

    #[test]
    fn analyze_workspace_invariants_suppresses_surface_rules_without_members() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();
        write_file(
            &root.join("Cargo.toml"),
            r#"[workspace]
members = ["missing_member"]
"#,
        );
        let report = scan_workspace(root).expect("scan workspace");
        assert!(report.members.is_empty());

        let analysis = analyze_workspace_invariants(&report);
        for suppressed_rule in [
            "cancel_phase_surface",
            "obligation_surface",
            "structured_concurrency_surface",
        ] {
            let trace = analysis
                .rule_traces
                .iter()
                .find(|candidate| candidate.rule_id == suppressed_rule)
                .expect("suppressed trace");
            assert_eq!(trace.outcome, "suppressed");
            assert_eq!(
                trace.suppressed_reason.as_deref(),
                Some("no members discovered")
            );
        }
        assert!(
            analysis
                .findings
                .iter()
                .any(|finding| finding.rule_id == "scanner_warning_integrity")
        );
    }

    #[test]
    fn analyze_workspace_invariants_is_deterministic() {
        let report = make_single_member_workspace_report(
            "use asupersync::Cx;\nuse asupersync::Scope;\nuse asupersync::cancel::CancelReason;\nuse asupersync::obligation::Obligation;\n",
        );
        let first = analyze_workspace_invariants(&report);
        let second = analyze_workspace_invariants(&report);
        assert_eq!(first, second);
        assert_eq!(first.rule_traces.len(), 5);
        assert!(
            first
                .rule_traces
                .iter()
                .any(|trace| trace.rule_id == "structured_concurrency_surface"
                    && trace.outcome == "pass")
        );
        assert!(
            first
                .rule_traces
                .iter()
                .any(|trace| trace.rule_id == "scan_lifecycle_events" && trace.outcome == "pass")
        );
    }

    #[test]
    fn analyze_workspace_lock_contention_detects_violation_and_hotspots() {
        let report = make_single_member_workspace_report(
            r"
struct RuntimeState;
impl RuntimeState {
    fn bad_order(&self) {
        let _tasks = self.tasks.lock();
        let _regions = self.regions.lock();
        let _obligations = self.obligations.lock();
    }

    fn contention_marker(&self) {
        let _instrumentation = self.instrumentation.lock();
        let lock_wait_ns = 1;
        let lock_hold_ns = 2;
    }
}
",
        );
        let analysis = analyze_workspace_lock_contention(&report);
        assert_eq!(analysis.analyzer_version, LOCK_CONTENTION_ANALYZER_VERSION);
        assert!(analysis.hotspot_count >= 1);
        assert!(analysis.violation_count >= 1);
        assert!(
            analysis
                .deadlock_risk_patterns
                .iter()
                .any(|pattern| pattern.contains("A(Tasks) -> B(Regions)"))
        );
        assert!(analysis.violations.iter().any(|violation| {
            violation
                .observed_transition
                .contains("A(Tasks) -> B(Regions)")
        }));
        let lock_rule = analysis
            .rule_traces
            .iter()
            .find(|trace| trace.rule_id == "lock_order_consistency")
            .expect("lock-order trace");
        assert_eq!(lock_rule.outcome, "fail");
        let deadlock_rule = analysis
            .rule_traces
            .iter()
            .find(|trace| trace.rule_id == "deadlock_risk_patterns")
            .expect("deadlock trace");
        assert_eq!(deadlock_rule.outcome, "fail");
    }

    #[test]
    fn analyze_workspace_lock_contention_ignores_comments_and_string_literals() {
        let report = make_single_member_workspace_report(
            r#"
impl RuntimeState {
    fn comments_and_strings_only(&self) {
        // let _tasks = self.tasks.lock();
        let _text = "self.regions.lock(); lock_wait_ns";
        let _char = '.';
    }
}
"#,
        );
        let analysis = analyze_workspace_lock_contention(&report);
        assert_eq!(analysis.hotspot_count, 0);
        assert_eq!(analysis.violation_count, 0);
        assert!(analysis.deadlock_risk_patterns.is_empty());
        let hotspot_rule = analysis
            .rule_traces
            .iter()
            .find(|trace| trace.rule_id == "contention_hotspot_ranking")
            .expect("hotspot trace");
        assert_eq!(hotspot_rule.outcome, "suppressed");
    }

    #[test]
    fn analyze_workspace_lock_contention_is_deterministic() {
        let report = make_single_member_workspace_report(
            r"
impl RuntimeState {
    fn deterministic_lock_path(&self) {
        let _config = self.config.lock();
        let _instrumentation = self.instrumentation.lock();
        let _regions = self.regions.lock();
        let _tasks = self.tasks.lock();
        let _obligations = self.obligations.lock();
    }
}
",
        );
        let first = analyze_workspace_lock_contention(&report);
        let second = analyze_workspace_lock_contention(&report);
        assert_eq!(first, second);
        assert!(
            first
                .rule_traces
                .iter()
                .any(|trace| trace.rule_id == "contention_hotspot_ranking")
        );
        assert!(
            first
                .rule_traces
                .iter()
                .any(|trace| trace.rule_id == "deadlock_risk_patterns")
        );
    }

    #[test]
    fn emit_lock_contention_structured_events_are_valid_and_deterministic() {
        let report = make_single_member_workspace_report(
            r"
impl RuntimeState {
    fn lock_path(&self) {
        let _tasks = self.tasks.lock();
        let _regions = self.regions.lock();
        // contention marker for scoring
        let lock_wait_ns = 0;
    }
}
",
        );
        let analysis = analyze_workspace_lock_contention(&report);
        let first = emit_lock_contention_structured_events(
            &analysis,
            "run-lock-contention-smoke",
            "doctor-lock-contention-smoke",
        )
        .expect("first events");
        let second = emit_lock_contention_structured_events(
            &analysis,
            "run-lock-contention-smoke",
            "doctor-lock-contention-smoke",
        )
        .expect("second events");
        assert_eq!(first, second);
        let contract = structured_logging_contract();
        validate_structured_logging_event_stream(&contract, &first).expect("valid event stream");
        assert!(
            first
                .iter()
                .any(|event| event.fields.contains_key("risk_score"))
        );
        assert!(
            first
                .iter()
                .any(|event| event.fields.contains_key("threshold_explanation"))
        );
    }

    #[test]
    fn operator_model_contract_validates() {
        let contract = operator_model_contract();
        validate_operator_model_contract(&contract).expect("valid operator contract");
    }

    #[test]
    fn operator_model_contract_is_deterministic() {
        let first = operator_model_contract();
        let second = operator_model_contract();
        assert_eq!(first, second);
    }

    #[test]
    fn operator_model_contract_round_trip_json() {
        let contract = operator_model_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: OperatorModelContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_operator_model_contract(&parsed).expect("parsed contract valid");
    }

    #[test]
    fn operator_model_contract_rejects_duplicate_persona_ids() {
        let mut contract = operator_model_contract();
        contract.personas.push(contract.personas[0].clone());
        let err = validate_operator_model_contract(&contract).expect_err("must fail");
        assert!(err.contains("duplicate persona id"), "{err}");
    }

    #[test]
    fn operator_model_contract_rejects_unsorted_mission_success_signals() {
        let mut contract = operator_model_contract();
        contract.personas[0].mission_success_signals =
            vec!["z_signal".to_string(), "a_signal".to_string()];
        let err = validate_operator_model_contract(&contract).expect_err("must fail");
        assert!(err.contains("mission_success_signals must be lexically sorted"));
    }

    #[test]
    fn operator_model_contract_rejects_unknown_decision_step_binding() {
        let mut contract = operator_model_contract();
        contract.personas[0].high_stakes_decisions[0].decision_step = "unknown_step".to_string();
        let err = validate_operator_model_contract(&contract).expect_err("must fail");
        assert!(err.contains("references unknown step"), "{err}");
    }

    #[test]
    fn operator_model_contract_rejects_decision_evidence_outside_contract() {
        let mut contract = operator_model_contract();
        contract.personas[0].high_stakes_decisions[0]
            .required_evidence
            .push("not_in_contract".to_string());
        contract.personas[0].high_stakes_decisions[0]
            .required_evidence
            .sort();
        let err = validate_operator_model_contract(&contract).expect_err("must fail");
        assert!(err.contains("references unknown evidence key"), "{err}");
    }

    #[test]
    fn operator_model_contract_navigation_topology_matches_screen_contract() {
        let contract = operator_model_contract();
        let topology_screens: BTreeSet<_> = contract
            .navigation_topology
            .screens
            .iter()
            .map(|screen| screen.id.clone())
            .collect();
        let screen_contract_screens: BTreeSet<_> = screen_engine_contract()
            .screens
            .iter()
            .map(|screen| screen.id.clone())
            .collect();
        assert_eq!(topology_screens, screen_contract_screens);
    }

    #[test]
    fn operator_model_contract_rejects_unsorted_navigation_screens() {
        let mut contract = operator_model_contract();
        contract.navigation_topology.screens.swap(0, 1);
        let err = validate_operator_model_contract(&contract).expect_err("must fail");
        assert!(
            err.contains("navigation_topology.screens must be lexically sorted by id"),
            "{err}"
        );
    }

    #[test]
    fn operator_model_contract_rejects_route_with_unknown_screen() {
        let mut contract = operator_model_contract();
        contract.navigation_topology.routes[0].to_screen = "unknown_screen".to_string();
        let err = validate_operator_model_contract(&contract).expect_err("must fail");
        assert!(err.contains("references unknown screen"), "{err}");
    }

    #[test]
    fn operator_model_contract_rejects_route_event_missing_core_field() {
        let mut contract = operator_model_contract();
        contract.navigation_topology.route_events[0]
            .required_fields
            .retain(|field| field != "trace_id");
        let err = validate_operator_model_contract(&contract).expect_err("must fail");
        assert!(err.contains("missing required field trace_id"), "{err}");
    }

    #[test]
    fn operator_model_contract_rejects_duplicate_keyboard_binding_scope_key() {
        let mut contract = operator_model_contract();
        contract
            .navigation_topology
            .keyboard_bindings
            .push(contract.navigation_topology.keyboard_bindings[0].clone());
        let err = validate_operator_model_contract(&contract).expect_err("must fail");
        assert!(
            err.contains("duplicate navigation keyboard binding"),
            "{err}"
        );
    }

    #[test]
    fn ux_signoff_matrix_contract_validates() {
        let contract = ux_signoff_matrix_contract();
        validate_ux_signoff_matrix_contract(&contract).expect("valid ux signoff matrix");
    }

    #[test]
    fn ux_signoff_matrix_contract_is_deterministic() {
        let first = ux_signoff_matrix_contract();
        let second = ux_signoff_matrix_contract();
        assert_eq!(first, second);
    }

    #[test]
    fn ux_signoff_matrix_contract_round_trip_json() {
        let contract = ux_signoff_matrix_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: UxSignoffMatrixContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_ux_signoff_matrix_contract(&parsed).expect("parsed ux signoff matrix valid");
    }

    #[test]
    fn ux_signoff_matrix_contract_rejects_unsorted_journeys() {
        let mut contract = ux_signoff_matrix_contract();
        contract.journeys.swap(0, 1);
        let err = validate_ux_signoff_matrix_contract(&contract).expect_err("must fail");
        assert!(
            err.contains("ux_signoff journeys must be lexically sorted by journey_id"),
            "{err}"
        );
    }

    #[test]
    fn ux_signoff_matrix_contract_rejects_transition_route_mismatch() {
        let mut contract = ux_signoff_matrix_contract();
        contract.journeys[0].transitions[0].route_ref =
            "route_incident_console_to_runtime_health".to_string();
        let err = validate_ux_signoff_matrix_contract(&contract).expect_err("must fail");
        assert!(err.contains("mismatches"), "{err}");
    }

    #[test]
    fn ux_signoff_matrix_contract_rejects_missing_interruption_assertions() {
        let mut contract = ux_signoff_matrix_contract();
        contract.journeys[1].interruption_assertions.clear();
        let err = validate_ux_signoff_matrix_contract(&contract).expect_err("must fail");
        assert!(
            err.contains("interruption_assertions must be non-empty"),
            "{err}"
        );
    }

    #[test]
    fn ux_signoff_matrix_contract_rejects_unknown_evidence_key() {
        let mut contract = ux_signoff_matrix_contract();
        contract.journeys[2].evidence_assertions[0]
            .required_evidence_keys
            .push("unknown_evidence_key".to_string());
        contract.journeys[2].evidence_assertions[0]
            .required_evidence_keys
            .sort();
        let err = validate_ux_signoff_matrix_contract(&contract).expect_err("must fail");
        assert!(err.contains("references unknown evidence key"), "{err}");
    }

    #[test]
    fn screen_engine_contract_validates() {
        let contract = screen_engine_contract();
        validate_screen_engine_contract(&contract).expect("valid screen contract");
    }

    #[test]
    fn screen_engine_contract_is_deterministic() {
        let first = screen_engine_contract();
        let second = screen_engine_contract();
        assert_eq!(first, second);
    }

    #[test]
    fn screen_engine_contract_round_trip_json() {
        let contract = screen_engine_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: ScreenEngineContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_screen_engine_contract(&parsed).expect("parsed screen contract valid");
    }

    #[test]
    fn screen_engine_contract_version_support_checks() {
        let contract = screen_engine_contract();
        let current_version = contract.contract_version.clone();
        assert!(is_screen_contract_version_supported(
            &contract,
            &current_version
        ));

        let mut with_legacy = contract.clone();
        with_legacy.compatibility.minimum_reader_version = current_version.clone();
        with_legacy.compatibility.supported_reader_versions = vec![
            "doctor-screen-engine-v0".to_string(),
            current_version.clone(),
        ];
        assert!(!is_screen_contract_version_supported(
            &with_legacy,
            "doctor-screen-engine-v0"
        ));

        let mut invalid = contract;
        invalid.compatibility.supported_reader_versions =
            vec![current_version, "doctor-screen-engine-v0".to_string()];
        let err = validate_screen_engine_contract(&invalid).expect_err("must fail");
        assert!(
            err.contains("supported_reader_versions must be lexically sorted"),
            "{err}"
        );
    }

    #[test]
    fn screen_exchange_enforces_required_fields_and_logs_rejection_context() {
        let contract = screen_engine_contract();
        let request = ScreenExchangeRequest {
            screen_id: "runtime_health".to_string(),
            correlation_id: "corr-001".to_string(),
            rerun_context: "br-2b4jj.1.1/run-001".to_string(),
            payload: BTreeMap::new(),
            outcome: ExchangeOutcome::Success,
        };

        let rejection = execute_screen_exchange(&contract, &request).expect_err("must reject");
        assert_eq!(rejection.contract_version, contract.contract_version);
        assert_eq!(rejection.correlation_id, request.correlation_id);
        assert_eq!(rejection.rerun_context, request.rerun_context);
        assert_eq!(
            rejection.validation_failures,
            vec![
                "missing required request field action".to_string(),
                "missing required request field focus_target".to_string(),
                "missing required request field run_id".to_string(),
            ]
        );
    }

    #[test]
    fn screen_exchange_executes_success_cancelled_and_failed_paths() {
        let contract = screen_engine_contract();
        let mut payload = BTreeMap::new();
        payload.insert("action".to_string(), "refresh".to_string());
        payload.insert("focus_target".to_string(), "runtime:core".to_string());
        payload.insert("run_id".to_string(), "run-001".to_string());

        for (outcome, expected_state, expected_class) in [
            (ExchangeOutcome::Success, "ready", "success"),
            (ExchangeOutcome::Cancelled, "cancelled", "cancelled"),
            (ExchangeOutcome::Failed, "failed", "failed"),
        ] {
            let request = ScreenExchangeRequest {
                screen_id: "runtime_health".to_string(),
                correlation_id: format!("corr-{expected_class}"),
                rerun_context: "br-2b4jj.1.1/run-002".to_string(),
                payload: payload.clone(),
                outcome,
            };

            let envelope = execute_screen_exchange(&contract, &request).expect("contract exchange");
            assert_eq!(envelope.contract_version, contract.contract_version);
            assert_eq!(envelope.screen_id, request.screen_id);
            assert_eq!(envelope.outcome_class, expected_class);
            assert_eq!(
                envelope.response_payload.get("state"),
                Some(&expected_state.to_string())
            );
            assert_eq!(
                envelope.response_payload.get("outcome_class"),
                Some(&expected_class.to_string())
            );
            assert_eq!(
                envelope.response_payload.get("confidence_score"),
                Some(&"1.0".to_string())
            );
            assert_eq!(
                envelope.response_payload.get("findings"),
                Some(&"[]".to_string())
            );
        }
    }

    #[test]
    fn visual_language_contract_validates() {
        let contract = visual_language_contract();
        validate_visual_language_contract(&contract).expect("valid visual contract");
    }

    #[test]
    fn visual_language_contract_is_deterministic() {
        let first = visual_language_contract();
        let second = visual_language_contract();
        assert_eq!(first, second);
    }

    #[test]
    fn visual_language_contract_round_trip_json() {
        let contract = visual_language_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: VisualLanguageContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_visual_language_contract(&parsed).expect("parsed visual contract valid");
    }

    #[test]
    fn visual_language_contract_rejects_unsorted_non_goals() {
        let mut contract = visual_language_contract();
        contract.non_goals = vec!["z".to_string(), "a".to_string()];
        let err = validate_visual_language_contract(&contract).expect_err("must fail");
        assert!(
            err.contains("non_goals must be unique and lexically sorted"),
            "{err}"
        );
    }

    #[test]
    fn visual_language_contract_rejects_capability_raising_fallback() {
        let mut contract = visual_language_contract();
        contract.profiles[0].fallback_profile_id = Some("showcase_truecolor".to_string());
        let err = validate_visual_language_contract(&contract).expect_err("must fail");
        assert!(
            err.contains("must not increase capability requirements"),
            "{err}"
        );
    }

    #[test]
    fn apply_visual_tokens_falls_back_for_ansi16() {
        let contract = visual_language_contract();
        let transcript = apply_visual_tokens(
            &contract,
            "incident_console",
            "corr-visual-1",
            TerminalCapabilityClass::Ansi16,
        )
        .expect("apply visual tokens");

        assert!(transcript.fallback_applied);
        assert_eq!(transcript.selected_profile_id, "showcase_ansi16");
        assert_eq!(
            transcript.applied_layout_motif,
            "priority queue + inline evidence bullets"
        );
        assert!(
            transcript
                .events
                .iter()
                .any(|event| event.event_kind == "theme_fallback")
        );
        assert!(
            transcript
                .events
                .iter()
                .any(|event| event.event_kind == "layout_degradation")
        );
    }

    #[test]
    fn apply_visual_tokens_logs_missing_role_event() {
        let mut contract = visual_language_contract();
        contract.profiles[0]
            .palette_tokens
            .retain(|token| token.role != "warning");

        let transcript = apply_visual_tokens(
            &contract,
            "bead_command_center",
            "corr-visual-2",
            TerminalCapabilityClass::Ansi16,
        )
        .expect("apply visual tokens");

        assert_eq!(transcript.missing_roles, vec!["warning".to_string()]);
        assert!(
            transcript
                .events
                .iter()
                .any(|event| event.event_kind == "token_resolution_failure")
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn apply_visual_tokens_viewport_matrix_snapshots_are_stable() {
        let contract = visual_language_contract();
        let scenarios = vec![
            (
                "bead_command_center",
                132_u16,
                44_u16,
                TerminalCapabilityClass::TrueColor,
            ),
            (
                "bead_command_center",
                96_u16,
                28_u16,
                TerminalCapabilityClass::TrueColor,
            ),
            (
                "incident_console",
                132_u16,
                44_u16,
                TerminalCapabilityClass::Ansi16,
            ),
            (
                "replay_inspector",
                120_u16,
                40_u16,
                TerminalCapabilityClass::Ansi256,
            ),
            (
                "replay_inspector",
                100_u16,
                30_u16,
                TerminalCapabilityClass::Ansi256,
            ),
        ];

        let mut observed = Vec::new();
        for (screen_id, width, height, capability) in scenarios {
            let correlation_id =
                format!("snapshot-{screen_id}-{width}x{height}-{capability:?}").to_lowercase();
            let transcript = apply_visual_tokens_for_viewport(
                &contract,
                screen_id,
                &correlation_id,
                capability,
                width,
                height,
            )
            .expect("apply visual tokens");

            let compact_viewport =
                width < MIN_VISUAL_VIEWPORT_WIDTH || height < MIN_VISUAL_VIEWPORT_HEIGHT;
            if compact_viewport {
                assert!(
                    transcript.events.iter().any(|event| {
                        event.event_kind == "layout_degradation"
                            && event
                                .message
                                .contains(&format!("viewport={width}x{height}"))
                    }),
                    "expected viewport degradation event for {screen_id} {width}x{height}"
                );
            }

            observed.push((
                screen_id.to_string(),
                format!("{width}x{height}"),
                format!("{capability:?}"),
                transcript.selected_profile_id,
                transcript.fallback_applied,
                transcript.applied_layout_motif,
                transcript.missing_roles,
                transcript
                    .events
                    .iter()
                    .map(|event| event.event_kind.clone())
                    .collect::<Vec<_>>(),
            ));
        }

        assert_eq!(
            observed,
            vec![
                (
                    "bead_command_center".to_string(),
                    "132x44".to_string(),
                    "TrueColor".to_string(),
                    "showcase_truecolor".to_string(),
                    false,
                    "triple-pane command runway".to_string(),
                    Vec::<String>::new(),
                    vec!["theme_selected".to_string()],
                ),
                (
                    "bead_command_center".to_string(),
                    "96x28".to_string(),
                    "TrueColor".to_string(),
                    "showcase_truecolor".to_string(),
                    false,
                    "stacked split with compact status badges".to_string(),
                    Vec::<String>::new(),
                    vec![
                        "theme_selected".to_string(),
                        "layout_degradation".to_string(),
                    ],
                ),
                (
                    "incident_console".to_string(),
                    "132x44".to_string(),
                    "Ansi16".to_string(),
                    "showcase_ansi16".to_string(),
                    true,
                    "priority queue + inline evidence bullets".to_string(),
                    Vec::<String>::new(),
                    vec![
                        "theme_fallback".to_string(),
                        "theme_fallback".to_string(),
                        "theme_selected".to_string(),
                        "layout_degradation".to_string(),
                    ],
                ),
                (
                    "replay_inspector".to_string(),
                    "120x40".to_string(),
                    "Ansi256".to_string(),
                    "showcase_ansi256".to_string(),
                    false,
                    "timeline + diff pane with synchronized cursor".to_string(),
                    Vec::<String>::new(),
                    vec!["theme_selected".to_string()],
                ),
                (
                    "replay_inspector".to_string(),
                    "100x30".to_string(),
                    "Ansi256".to_string(),
                    "showcase_ansi256".to_string(),
                    false,
                    "single timeline table with deterministic markers".to_string(),
                    Vec::<String>::new(),
                    vec![
                        "theme_selected".to_string(),
                        "layout_degradation".to_string(),
                    ],
                ),
            ]
        );
    }

    #[test]
    fn apply_visual_tokens_rejects_zero_viewport_dimensions() {
        let contract = visual_language_contract();
        let width_error = apply_visual_tokens_for_viewport(
            &contract,
            "bead_command_center",
            "corr-visual-viewport-width-zero",
            TerminalCapabilityClass::TrueColor,
            0,
            44,
        )
        .expect_err("zero width must fail");
        assert_eq!(width_error, "viewport_width must be greater than zero");

        let height_error = apply_visual_tokens_for_viewport(
            &contract,
            "bead_command_center",
            "corr-visual-viewport-height-zero",
            TerminalCapabilityClass::TrueColor,
            132,
            0,
        )
        .expect_err("zero height must fail");
        assert_eq!(height_error, "viewport_height must be greater than zero");
    }

    fn mixed_artifacts_fixture() -> Vec<RuntimeArtifact> {
        vec![
            RuntimeArtifact {
                artifact_id: "artifact-benchmark".to_string(),
                artifact_type: "benchmark".to_string(),
                source_path: "target/criterion/summary.txt".to_string(),
                replay_pointer:
                    "rch exec -- cargo bench --features criterion-benches --bench doctor_ingestion"
                        .to_string(),
                content: "throughput_gib_s=12.4\nlatency_p95_ms=4.1\n".to_string(),
            },
            RuntimeArtifact {
                artifact_id: "artifact-log".to_string(),
                artifact_type: "structured_log".to_string(),
                source_path: "logs/run-42.json".to_string(),
                replay_pointer: "rch exec -- cargo test -p asupersync -- --nocapture".to_string(),
                content: r#"{
  "correlation_id": "corr-42",
  "scenario_id": "doctor-smoke",
  "seed": "42",
  "outcome_class": "cancelled",
  "summary": "operator cancelled after triage"
}"#
                .to_string(),
            },
            RuntimeArtifact {
                artifact_id: "artifact-trace".to_string(),
                artifact_type: "trace".to_string(),
                source_path: "trace/run-42.trace.json".to_string(),
                replay_pointer: "asupersync trace verify trace/run-42.trace.json".to_string(),
                content: r#"{
  "trace_id": "trace-42",
  "scenario_id": "doctor-smoke",
  "seed": 42,
  "outcome_class": "success",
  "message": "trace verification complete"
}"#
                .to_string(),
            },
            RuntimeArtifact {
                artifact_id: "artifact-ubs".to_string(),
                artifact_type: "ubs_findings".to_string(),
                source_path: "ubs-output.txt".to_string(),
                replay_pointer: "ubs src/cli/doctor/mod.rs".to_string(),
                content: "src/cli/doctor/mod.rs:10:5 issue A\nsrc/cli/doctor/mod.rs:20:7 issue B\n"
                    .to_string(),
            },
        ]
    }

    fn source_adapter_matrix_fixture() -> Vec<RuntimeArtifact> {
        vec![
            RuntimeArtifact {
                artifact_id: "browser-package".to_string(),
                artifact_type: "browser_package_readiness".to_string(),
                source_path: "docs/wasm_browser_artifact_integrity_manifest_v1.json".to_string(),
                replay_pointer: "bash scripts/build_browser_core_artifacts.sh prod".to_string(),
                content: r#"{
  "correlation_id": "browser-package",
  "scenario_id": "browser-ga",
  "seed": "none",
  "outcome_class": "success",
  "summary": "browser package manifest verified"
}"#
                .to_string(),
            },
            RuntimeArtifact {
                artifact_id: "cargo-graph".to_string(),
                artifact_type: "cargo_feature_graph".to_string(),
                source_path: "target/cargo-tree/default.txt".to_string(),
                replay_pointer: "rch exec -- cargo tree -e normal -p asupersync".to_string(),
                content: "asupersync v0.3.4\nserde v1.0.0\n".to_string(),
            },
            RuntimeArtifact {
                artifact_id: "proof-lane".to_string(),
                artifact_type: "proof_lane_manifest".to_string(),
                source_path: "artifacts/proof_lane_manifest_v1.json".to_string(),
                replay_pointer: "rch exec -- cargo test --test proof_lane_manifest_contract"
                    .to_string(),
                content: r#"{
  "correlation_id": "proof-lane",
  "scenario_id": "proof-manifest",
  "seed": "none",
  "outcome_class": "success",
  "summary": "manifest row parsed"
}"#
                .to_string(),
            },
            RuntimeArtifact {
                artifact_id: "proof-status".to_string(),
                artifact_type: "proof_status".to_string(),
                source_path: "artifacts/proof_status_snapshot_v1.json".to_string(),
                replay_pointer: "rch exec -- cargo test --test proof_status_snapshot_contract"
                    .to_string(),
                content: r#"{
  "correlation_id": "proof-status",
  "scenario_id": "proof-status",
  "seed": "none",
  "outcome_class": "success",
  "summary": "snapshot row parsed"
}"#
                .to_string(),
            },
            RuntimeArtifact {
                artifact_id: "rch-preflight".to_string(),
                artifact_type: "rch_receipt".to_string(),
                source_path: "target/rch/topology-preflight.json".to_string(),
                replay_pointer: "RCH_REQUIRE_REMOTE=1 rch exec -- cargo test ...".to_string(),
                content: r#"{
  "correlation_id": "rch-preflight",
  "scenario_id": "topology-preflight",
  "seed": "none",
  "outcome_class": "failed",
  "summary": "remote topology preflight failed before Cargo"
}"#
                .to_string(),
            },
            RuntimeArtifact {
                artifact_id: "redacted-log".to_string(),
                artifact_type: "redacted_log".to_string(),
                source_path: "logs/doctor-redacted.json".to_string(),
                replay_pointer: "asupersync doctor collect-logs --redact".to_string(),
                content: r#"{
  "correlation_id": "redacted-log",
  "scenario_id": "doctor-log",
  "seed": "none",
  "outcome_class": "success",
  "summary": "token=[REDACTED]"
}"#
                .to_string(),
            },
            RuntimeArtifact {
                artifact_id: "runtime-inspector".to_string(),
                artifact_type: "runtime_inspector".to_string(),
                source_path: "target/runtime-inspector/snapshot.json".to_string(),
                replay_pointer: "asupersync doctor runtime-inspector --json".to_string(),
                content: r#"{
  "correlation_id": "runtime-inspector",
  "scenario_id": "runtime-health",
  "seed": "none",
  "outcome_class": "success",
  "summary": "runtime inspector snapshot parsed"
}"#
                .to_string(),
            },
            RuntimeArtifact {
                artifact_id: "tracker-context".to_string(),
                artifact_type: "tracker_context".to_string(),
                source_path: ".beads/issues.jsonl".to_string(),
                replay_pointer: "br show asupersync-idea-wizard-fifth-wave-3gaiun.1.1 --json"
                    .to_string(),
                content: r#"{
  "correlation_id": "tracker-context",
  "scenario_id": "doctor-d1",
  "seed": "none",
  "outcome_class": "success",
  "summary": "bead context parsed"
}"#
                .to_string(),
            },
            RuntimeArtifact {
                artifact_id: "unredacted-log".to_string(),
                artifact_type: "redacted_log".to_string(),
                source_path: "logs/raw.json".to_string(),
                replay_pointer: "asupersync doctor collect-logs".to_string(),
                content: r#"{
  "correlation_id": "raw-log",
  "scenario_id": "doctor-log",
  "seed": "none",
  "outcome_class": "failed",
  "summary": "UNREDACTED_SECRET token leaked"
}"#
                .to_string(),
            },
        ]
    }

    fn evidence_analysis_d2_fixture() -> Vec<RuntimeArtifact> {
        vec![
            RuntimeArtifact {
                artifact_id: "local-fallback-marker".to_string(),
                artifact_type: "proof_status".to_string(),
                source_path: "artifacts/proof-status-local.json".to_string(),
                replay_pointer:
                    "RCH_REQUIRE_REMOTE=1 rch exec -- cargo check -p asupersync --features cli --lib"
                        .to_string(),
                content: r#"{
  "correlation_id": "local-fallback-marker",
  "scenario_id": "doctor-d2-local-fallback",
  "seed": "none",
  "outcome_class": "failed",
  "summary": "no-local-fallback violation: local fallback marker location=local"
}"#
                .to_string(),
            },
            RuntimeArtifact {
                artifact_id: "obligation-leak".to_string(),
                artifact_type: "runtime_inspector".to_string(),
                source_path: "artifacts/runtime-obligation.json".to_string(),
                replay_pointer: "rch exec -- cargo test --features test-internals obligation"
                    .to_string(),
                content: r#"{
  "correlation_id": "obligation-leak",
  "scenario_id": "doctor-d2-obligation",
  "seed": "none",
  "outcome_class": "failed",
  "summary": "ASUP-E101 obligation leak: permit leak in channel reserve path"
}"#
                .to_string(),
            },
            RuntimeArtifact {
                artifact_id: "proof-artifact-rejected".to_string(),
                artifact_type: "proof_status".to_string(),
                source_path: "artifacts/proof-status-malformed.json".to_string(),
                replay_pointer: "rch exec -- cargo test --test proof_status_snapshot_contract"
                    .to_string(),
                content: "not-json".to_string(),
            },
            RuntimeArtifact {
                artifact_id: "stale-rch-proof".to_string(),
                artifact_type: "rch_receipt".to_string(),
                source_path: "artifacts/rch-stale-progress.json".to_string(),
                replay_pointer:
                    "RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --features cli"
                        .to_string(),
                content: r#"{
  "correlation_id": "stale-rch-proof",
  "scenario_id": "doctor-d2-rch",
  "seed": "none",
  "outcome_class": "failed",
  "summary": "heartbeat live but progress-stale stuck_detector cancelled proof"
}"#
                .to_string(),
            },
        ]
    }

    fn doctor_evidence_bundle(
        run_id: &str,
        source_profile: &str,
        artifacts: Vec<RuntimeArtifact>,
    ) -> DoctorEvidenceBundle {
        DoctorEvidenceBundle {
            schema_version: DOCTOR_EVIDENCE_SCHEMA_VERSION.to_string(),
            bundle_id: format!("bundle-{run_id}"),
            run_id: run_id.to_string(),
            source_profile: source_profile.to_string(),
            generated_by: "doctor-module-fixture".to_string(),
            artifacts,
        }
    }

    #[test]
    fn evidence_adapter_specs_cover_doctor_d1_sources() {
        let specs = supported_evidence_adapter_specs();
        let artifact_types = specs
            .iter()
            .map(|spec| spec.artifact_type.as_str())
            .collect::<BTreeSet<_>>();
        for required in [
            "runtime_inspector",
            "proof_status",
            "proof_lane_manifest",
            "rch_receipt",
            "browser_package_readiness",
            "cargo_feature_graph",
            "tracker_context",
            "redacted_log",
        ] {
            assert!(
                artifact_types.contains(required),
                "missing doctor evidence adapter {required}"
            );
        }
        for spec in specs {
            assert_eq!(spec.adapter_version, EVIDENCE_ADAPTER_VERSION);
            assert!(
                spec.no_claim_boundary.starts_with("does_not_prove:"),
                "{} missing no-claim boundary",
                spec.artifact_type
            );
            assert!(
                spec.redaction_policy.ends_with("-v1"),
                "{} missing stable redaction policy",
                spec.artifact_type
            );
        }
    }

    #[test]
    fn doctor_evidence_bundle_validates_and_ingests_source_adapter_matrix() {
        let bundle = doctor_evidence_bundle(
            "run-doctor-d1-bundle",
            "source_adapter_matrix_v1",
            source_adapter_matrix_fixture(),
        );
        validate_doctor_evidence_bundle(&bundle).expect("bundle should validate");

        let report = ingest_doctor_evidence_bundle(&bundle);
        validate_evidence_ingestion_report(&report).expect("report should validate");
        assert_eq!(report.schema_version, DOCTOR_EVIDENCE_SCHEMA_VERSION);
        assert_eq!(report.run_id, "run-doctor-d1-bundle");
        assert_eq!(report.records.len(), 9);
        assert_eq!(report.rejected.len(), 1);
        assert!(
            report.records.iter().all(|record| !record
                .provenance
                .no_claim_boundary
                .trim()
                .is_empty())
        );
    }

    #[test]
    fn doctor_evidence_bundle_rejects_unknown_schema_fail_closed() {
        let mut bundle = doctor_evidence_bundle(
            "run-doctor-d1-bad-schema",
            "mixed_artifacts_v1",
            mixed_artifacts_fixture(),
        );
        bundle.schema_version = "doctor-evidence-v2".to_string();

        let validation_error =
            validate_doctor_evidence_bundle(&bundle).expect_err("schema must fail");
        assert!(
            validation_error.contains("unsupported DoctorEvidenceBundle schema_version"),
            "{validation_error}"
        );

        let report = ingest_doctor_evidence_bundle(&bundle);
        validate_evidence_ingestion_report(&report).expect("fail-closed report validates");
        assert_eq!(report.records.len(), 0);
        assert_eq!(report.rejected.len(), 1);
        assert_eq!(report.rejected[0].artifact_id, "doctor_evidence_bundle");
        assert!(
            report.rejected[0]
                .reason
                .contains("unsupported DoctorEvidenceBundle schema_version"),
            "{}",
            report.rejected[0].reason
        );
        assert!(report.events.iter().any(|event| {
            event.stage == "reject_bundle"
                && event.artifact_id.as_deref() == Some("doctor_evidence_bundle")
        }));
    }

    #[test]
    fn doctor_evidence_bundle_rejects_empty_artifacts() {
        let bundle =
            doctor_evidence_bundle("run-doctor-d1-empty", "empty_artifacts_v1", Vec::new());
        let validation_error =
            validate_doctor_evidence_bundle(&bundle).expect_err("empty bundle must fail");
        assert_eq!(
            validation_error,
            "DoctorEvidenceBundle artifacts must be non-empty"
        );

        let report = ingest_doctor_evidence_bundle(&bundle);
        validate_evidence_ingestion_report(&report).expect("fail-closed report validates");
        assert_eq!(report.records.len(), 0);
        assert_eq!(report.rejected.len(), 1);
        assert_eq!(
            report.rejected[0].reason,
            "DoctorEvidenceBundle artifacts must be non-empty"
        );
    }

    #[test]
    fn doctor_evidence_bundle_rejects_empty_provenance_metadata() {
        let mut bundle = doctor_evidence_bundle(
            "run-doctor-d1-metadata",
            "mixed_artifacts_v1",
            mixed_artifacts_fixture(),
        );
        bundle.bundle_id.clear();

        let validation_error =
            validate_doctor_evidence_bundle(&bundle).expect_err("empty bundle_id must fail");
        assert_eq!(
            validation_error,
            "DoctorEvidenceBundle bundle_id must be non-empty"
        );

        let report = ingest_doctor_evidence_bundle(&bundle);
        validate_evidence_ingestion_report(&report).expect("fail-closed report validates");
        assert_eq!(report.records.len(), 0);
        assert_eq!(report.rejected.len(), 1);
        assert_eq!(
            report.rejected[0].reason,
            "DoctorEvidenceBundle bundle_id must be non-empty"
        );
    }

    #[test]
    fn evidence_ingestion_accepts_source_adapter_matrix_and_rejects_raw_secret() {
        let report = ingest_runtime_artifacts("run-doctor-d1", &source_adapter_matrix_fixture());
        validate_evidence_ingestion_report(&report).expect("report should validate");
        assert_eq!(report.records.len(), 9);
        assert_eq!(report.rejected.len(), 1);
        assert_eq!(
            report.rejected[0].reason,
            "artifact contains unredacted secret marker"
        );

        let source_kinds = report
            .records
            .iter()
            .map(|record| record.provenance.source_kind.as_str())
            .collect::<BTreeSet<_>>();
        for required in [
            "runtime_inspector_snapshot",
            "proof_status_snapshot",
            "proof_lane_manifest_row",
            "rch_receipt",
            "browser_package_readiness",
            "cargo_feature_graph_snippet",
            "tracker_context",
            "redacted_log",
        ] {
            assert!(
                source_kinds.contains(required),
                "missing normalized source kind {required}"
            );
        }
        assert!(report.records.iter().all(|record| {
            record
                .provenance
                .no_claim_boundary
                .starts_with("does_not_prove:")
        }));
    }

    #[test]
    fn doctor_evidence_analysis_maps_findings_and_recipes() {
        let ingestion_report =
            ingest_runtime_artifacts("run-doctor-d2", &evidence_analysis_d2_fixture());
        validate_evidence_ingestion_report(&ingestion_report).expect("ingestion report validates");

        let analysis = analyze_doctor_evidence_report(&ingestion_report);
        let analysis_again = analyze_doctor_evidence_report(&ingestion_report);
        assert_eq!(analysis, analysis_again);
        validate_doctor_evidence_analysis_report(&analysis).expect("analysis validates");
        assert_eq!(analysis.finding_count, 4);

        let families = analysis
            .findings
            .iter()
            .map(|finding| finding.diagnostic_family.as_str())
            .collect::<BTreeSet<_>>();
        for expected in [
            "local_fallback_marker",
            "missing_proof_artifact",
            "obligation_leak",
            "stale_rch_proof",
        ] {
            assert!(families.contains(expected), "missing family {expected}");
        }

        let risk_classes = analysis
            .findings
            .iter()
            .filter_map(|finding| finding.remediation_recipe.as_ref())
            .map(|recipe| recipe.risk_class.as_str())
            .collect::<BTreeSet<_>>();
        for expected in [
            "destructive-forbidden",
            "edit-suggestion",
            "observe",
            "rerun",
        ] {
            assert!(
                risk_classes.contains(expected),
                "missing risk class {expected}"
            );
        }

        assert!(analysis.findings.iter().any(|finding| {
            finding
                .asup_error_code
                .as_deref()
                .is_some_and(|code| code.contains("ASUP-E101"))
        }));
        assert!(analysis.findings.iter().all(|finding| {
            finding.next_proof_command.contains("rch")
                || finding.next_proof_command.contains("RCH_REQUIRE_REMOTE")
        }));
    }

    #[test]
    fn evidence_ingestion_normalizes_mixed_bundle_and_validates() {
        let report = ingest_runtime_artifacts("run-42", &mixed_artifacts_fixture());
        validate_evidence_ingestion_report(&report).expect("report should validate");
        assert_eq!(report.schema_version, EVIDENCE_SCHEMA_VERSION);
        assert_eq!(report.rejected.len(), 0);
        assert_eq!(report.records.len(), 6);

        let cancelled = report
            .records
            .iter()
            .find(|record| record.artifact_id == "artifact-log")
            .expect("cancelled record");
        assert_eq!(cancelled.outcome_class, "cancelled");
        assert_eq!(cancelled.correlation_id, "corr-42");
    }

    #[test]
    fn evidence_ingestion_rejects_malformed_json_and_tracks_reason() {
        let artifacts = vec![RuntimeArtifact {
            artifact_id: "bad-log".to_string(),
            artifact_type: "structured_log".to_string(),
            source_path: "logs/bad.json".to_string(),
            replay_pointer: "replay bad".to_string(),
            content: "{not json}".to_string(),
        }];

        let report = ingest_runtime_artifacts("run-bad", &artifacts);
        assert_eq!(report.records.len(), 0);
        assert_eq!(report.rejected.len(), 1);
        assert!(
            report.rejected[0].reason.contains("invalid JSON payload"),
            "{}",
            report.rejected[0].reason
        );
        let has_rejection_event = report.events.iter().any(|event| {
            event.stage == "reject_artifact"
                && event.artifact_id.as_deref() == Some("bad-log")
                && event.replay_pointer.as_deref() == Some("replay bad")
        });
        assert!(has_rejection_event, "expected reject_artifact event");
    }

    #[test]
    fn evidence_ingestion_deduplicates_records_deterministically() {
        let duplicate_trace = RuntimeArtifact {
            artifact_id: "trace-dup-a".to_string(),
            artifact_type: "trace".to_string(),
            source_path: "trace/a.json".to_string(),
            replay_pointer: "trace replay a".to_string(),
            content: r#"{"correlation_id":"corr-dup","scenario_id":"s","seed":"1","outcome_class":"success","summary":"same"}"#.to_string(),
        };
        let duplicate_trace_b = RuntimeArtifact {
            artifact_id: "trace-dup-b".to_string(),
            artifact_type: "trace".to_string(),
            source_path: "trace/b.json".to_string(),
            replay_pointer: "trace replay b".to_string(),
            content: duplicate_trace.content.clone(),
        };

        let report = ingest_runtime_artifacts("run-dedupe", &[duplicate_trace, duplicate_trace_b]);
        validate_evidence_ingestion_report(&report).expect("report should validate");
        assert_eq!(report.records.len(), 1);
        let dedupe_events = report
            .events
            .iter()
            .filter(|event| event.stage == "dedupe_record")
            .count();
        assert_eq!(dedupe_events, 1);
    }

    #[test]
    fn evidence_ingestion_e2e_replay_is_stable_across_repeated_runs() {
        let first = ingest_runtime_artifacts("run-e2e", &mixed_artifacts_fixture());
        let second = ingest_runtime_artifacts("run-e2e", &mixed_artifacts_fixture());
        assert_eq!(first, second);
        validate_evidence_ingestion_report(&first).expect("first report valid");
        validate_evidence_ingestion_report(&second).expect("second report valid");
    }

    #[test]
    fn structured_logging_contract_validates() {
        let contract = structured_logging_contract();
        validate_structured_logging_contract(&contract).expect("valid logging contract");
    }

    #[test]
    fn structured_logging_contract_round_trip_json() {
        let contract = structured_logging_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: StructuredLoggingContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_structured_logging_contract(&parsed).expect("parsed contract valid");
    }

    #[test]
    fn structured_logging_contract_rejects_unsorted_event_taxonomy() {
        let mut contract = structured_logging_contract();
        contract.event_taxonomy = vec![
            "verification_summary".to_string(),
            "command_start".to_string(),
        ];
        let err = validate_structured_logging_contract(&contract).expect_err("must fail");
        assert!(
            err.contains("event_taxonomy must be lexically sorted"),
            "{err}"
        );
    }

    #[test]
    fn emit_structured_log_event_enforces_required_fields() {
        let contract = structured_logging_contract();
        let mut fields = BTreeMap::new();
        fields.insert(
            "artifact_pointer".to_string(),
            "artifacts/run-1/execution/start.json".to_string(),
        );
        fields.insert(
            "command_provenance".to_string(),
            "rch exec -- cargo test".to_string(),
        );
        fields.insert("flow_id".to_string(), "execution".to_string());
        fields.insert("outcome_class".to_string(), "success".to_string());
        fields.insert("run_id".to_string(), "run-1".to_string());
        fields.insert(
            "scenario_id".to_string(),
            "doctor-execution-smoke".to_string(),
        );

        let err = emit_structured_log_event(&contract, "execution", "command_start", &fields)
            .expect_err("missing trace_id must fail");
        assert!(err.contains("missing required field trace_id"), "{err}");
    }

    #[test]
    fn emit_structured_log_event_enforces_format_rules() {
        let contract = structured_logging_contract();
        let mut fields = BTreeMap::new();
        fields.insert(
            "artifact_pointer".to_string(),
            "artifacts/run-1/execution/start.json".to_string(),
        );
        fields.insert(
            "command_provenance".to_string(),
            "rch exec -- cargo test".to_string(),
        );
        fields.insert("flow_id".to_string(), "execution".to_string());
        fields.insert("outcome_class".to_string(), "success".to_string());
        fields.insert("run_id".to_string(), "run-1".to_string());
        fields.insert("scenario_id".to_string(), "Doctor Scenario".to_string());
        fields.insert("trace_id".to_string(), "trace-1".to_string());

        let err = emit_structured_log_event(&contract, "execution", "command_start", &fields)
            .expect_err("invalid scenario_id must fail");
        assert!(
            err.contains("invalid field format for scenario_id"),
            "{err}"
        );
    }

    #[test]
    fn structured_logging_smoke_run_is_deterministic_and_validates() {
        let contract = structured_logging_contract();
        let first = run_structured_logging_smoke(&contract, "run-logging-smoke").expect("smoke");
        let second = run_structured_logging_smoke(&contract, "run-logging-smoke").expect("smoke");
        assert_eq!(first, second);
        validate_structured_logging_event_stream(&contract, &first).expect("stream valid");

        let mut observed_flows = BTreeSet::new();
        for event in &first {
            observed_flows.insert(event.flow_id.clone());
        }
        assert_eq!(
            observed_flows.into_iter().collect::<Vec<_>>(),
            vec![
                "execution".to_string(),
                "integration".to_string(),
                "remediation".to_string(),
                "replay".to_string(),
            ]
        );
    }

    #[test]
    fn structured_logging_event_stream_rejects_out_of_order_events() {
        let contract = structured_logging_contract();
        let mut events = run_structured_logging_smoke(&contract, "run-ordering").expect("smoke");
        events.reverse();

        let err = validate_structured_logging_event_stream(&contract, &events)
            .expect_err("reversed events must fail ordering");
        assert!(
            err.contains("events must be lexically ordered by flow_id/event_kind/trace_id"),
            "{err}"
        );
    }

    #[test]
    fn remediation_recipe_contract_validates() {
        let contract = remediation_recipe_contract();
        validate_remediation_recipe_contract(&contract).expect("valid remediation recipe contract");
    }

    #[test]
    fn remediation_recipe_contract_round_trip_json() {
        let contract = remediation_recipe_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: RemediationRecipeContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_remediation_recipe_contract(&parsed).expect("parsed contract valid");
    }

    #[test]
    fn parse_remediation_recipe_rejects_unknown_fix_intent() {
        let contract = remediation_recipe_contract();
        let mut bad = remediation_recipe_fixtures()
            .first()
            .expect("fixture")
            .recipe
            .clone();
        bad.fix_intent = "rewrite_runtime_in_one_shot".to_string();
        let payload = serde_json::to_string(&bad).expect("serialize");

        let err = parse_remediation_recipe(&contract, &payload).expect_err("must fail");
        assert!(err.contains("unsupported fix_intent"), "{err}");
    }

    #[test]
    fn remediation_confidence_score_is_deterministic() {
        let contract = remediation_recipe_contract();
        let fixture = remediation_recipe_fixtures()
            .first()
            .expect("fixture")
            .recipe
            .clone();

        let first = compute_remediation_confidence_score(&contract, &fixture).expect("score");
        let second = compute_remediation_confidence_score(&contract, &fixture).expect("score");
        assert_eq!(first, second);
        assert_eq!(first.confidence_score, 80);
        assert_eq!(first.risk_band, "guarded_auto_apply".to_string());
    }

    #[test]
    fn remediation_recipe_smoke_is_deterministic_and_logs_decision_context() {
        let recipe_contract = remediation_recipe_contract();
        let logging_contract = structured_logging_contract();

        let first =
            run_remediation_recipe_smoke(&recipe_contract, &logging_contract).expect("smoke");
        let second =
            run_remediation_recipe_smoke(&recipe_contract, &logging_contract).expect("smoke");
        assert_eq!(first, second);
        validate_structured_logging_event_stream(&logging_contract, &first)
            .expect("event stream valid");

        let has_rejection = first.iter().any(|event| {
            event
                .fields
                .get("rejection_rationale")
                .is_some_and(|value| !value.trim().is_empty())
        });
        assert!(
            has_rejection,
            "smoke stream should include rejection rationale"
        );
    }

    // ── guided remediation pipeline tests (2b4jj.4.2) ──────────────────

    #[test]
    fn guided_patch_plan_high_confidence_recipe_has_low_residual_risk() {
        let contract = remediation_recipe_contract();
        let recipe = remediation_recipe_fixtures()
            .first()
            .expect("fixture")
            .recipe
            .clone();
        let plan = build_guided_remediation_patch_plan(&contract, &recipe).expect("plan");

        assert_eq!(plan.plan_id, "plan-lock-order-001");
        assert_eq!(plan.recipe_id, "recipe-lock-order-001");
        assert_eq!(plan.finding_id, recipe.finding_id);
        assert_eq!(plan.risk_flags, vec!["low_residual_risk"]);
        assert_eq!(plan.approval_checkpoints.len(), 4);
        assert!(!plan.rollback_artifact_pointer.is_empty());
        assert!(!plan.rollback_instructions.is_empty());
        assert!(!plan.operator_guidance.is_empty());
        assert!(!plan.idempotency_key.is_empty());
        assert!(!plan.diff_preview.is_empty());
        assert!(!plan.impacted_invariants.is_empty());
    }

    #[test]
    fn guided_patch_plan_low_confidence_recipe_flags_risk_guardrails() {
        let contract = remediation_recipe_contract();
        let recipe = remediation_recipe_fixtures()
            .get(1)
            .expect("low-confidence fixture")
            .recipe
            .clone();
        let plan = build_guided_remediation_patch_plan(&contract, &recipe).expect("plan");

        assert!(
            plan.risk_flags
                .contains(&"human_approval_required".to_string()),
            "low-confidence plan must flag human_approval_required: {:?}",
            plan.risk_flags
        );
        assert!(
            plan.risk_flags.contains(&"auto_apply_blocked".to_string()),
            "low-confidence plan must flag auto_apply_blocked: {:?}",
            plan.risk_flags
        );
        assert!(
            plan.risk_flags
                .contains(&"confidence_below_auto_apply_threshold".to_string()),
            "score<70 must flag confidence_below_auto_apply_threshold: {:?}",
            plan.risk_flags
        );
        assert!(
            plan.risk_flags
                .contains(&"operator_override_requested".to_string()),
            "recipe with override_justification must flag operator_override_requested: {:?}",
            plan.risk_flags
        );
    }

    #[test]
    fn guided_patch_plan_diff_preview_references_correct_file() {
        let contract = remediation_recipe_contract();
        let recipe = remediation_recipe_fixtures()
            .first()
            .expect("fixture")
            .recipe
            .clone();
        let plan = build_guided_remediation_patch_plan(&contract, &recipe).expect("plan");

        let expected_path = "src/runtime/state.rs";
        assert!(
            plan.diff_preview
                .iter()
                .any(|line| line.contains(expected_path)),
            "diff_preview should reference patch target from finding_id: {:?}",
            plan.diff_preview
        );
    }

    #[test]
    fn guided_patch_plan_rollback_instructions_contain_all_components() {
        let contract = remediation_recipe_contract();
        let recipe = remediation_recipe_fixtures()
            .first()
            .expect("fixture")
            .recipe
            .clone();
        let plan = build_guided_remediation_patch_plan(&contract, &recipe).expect("plan");

        let joined = plan.rollback_instructions.join("|");
        assert!(
            joined.contains("rollback_command="),
            "must include rollback_command"
        );
        assert!(
            joined.contains("verify_command="),
            "must include verify_command"
        );
        assert!(
            joined.contains("timeout_secs="),
            "must include timeout_secs"
        );
        assert!(
            joined.contains("rollback_artifact_pointer="),
            "must include rollback_artifact_pointer"
        );
    }

    #[test]
    fn guided_patch_plan_idempotency_key_is_deterministic() {
        let contract = remediation_recipe_contract();
        let recipe = remediation_recipe_fixtures()
            .first()
            .expect("fixture")
            .recipe
            .clone();
        let plan1 = build_guided_remediation_patch_plan(&contract, &recipe).expect("plan1");
        let plan2 = build_guided_remediation_patch_plan(&contract, &recipe).expect("plan2");

        assert_eq!(plan1.idempotency_key, plan2.idempotency_key);
        assert_eq!(plan1.patch_digest, plan2.patch_digest);
        assert_eq!(plan1.plan_id, plan2.plan_id);
    }

    #[test]
    fn guided_session_apply_success_bumps_trust_and_emits_four_events() {
        let recipe_contract = remediation_recipe_contract();
        let logging_contract = structured_logging_contract();
        let recipe = remediation_recipe_fixtures()
            .first()
            .expect("fixture")
            .recipe
            .clone();
        let plan = build_guided_remediation_patch_plan(&recipe_contract, &recipe).expect("plan");
        let approvals = plan
            .approval_checkpoints
            .iter()
            .map(|cp| cp.checkpoint_id.clone())
            .collect::<Vec<_>>();

        let outcome = run_guided_remediation_session(
            &recipe_contract,
            &logging_contract,
            &recipe,
            &GuidedRemediationSessionRequest {
                run_id: "run-test-success".to_string(),
                scenario_id: "test-apply-success".to_string(),
                approved_checkpoints: approvals,
                inject_apply_failure: false,
                previous_idempotency_key: None,
            },
        )
        .expect("session");

        assert_eq!(outcome.apply_status, "applied");
        assert_eq!(outcome.verify_status, "verified");
        assert!(
            outcome.trust_score_after > outcome.trust_score_before,
            "trust should increase on success: before={} after={}",
            outcome.trust_score_before,
            outcome.trust_score_after
        );
        assert_eq!(
            outcome.trust_score_after,
            outcome.trust_score_before.saturating_add(10).min(100)
        );
        assert_eq!(
            outcome.events.len(),
            4,
            "must emit preview+apply+verify+summary"
        );

        validate_structured_logging_event_stream(&logging_contract, &outcome.events)
            .expect("event stream valid");
    }

    #[test]
    fn guided_session_blocked_pending_approval_lowers_trust() {
        let recipe_contract = remediation_recipe_contract();
        let logging_contract = structured_logging_contract();
        let recipe = remediation_recipe_fixtures()
            .first()
            .expect("fixture")
            .recipe
            .clone();

        let outcome = run_guided_remediation_session(
            &recipe_contract,
            &logging_contract,
            &recipe,
            &GuidedRemediationSessionRequest {
                run_id: "run-test-blocked".to_string(),
                scenario_id: "test-blocked".to_string(),
                approved_checkpoints: vec![],
                inject_apply_failure: false,
                previous_idempotency_key: None,
            },
        )
        .expect("session");

        assert_eq!(outcome.apply_status, "blocked_pending_approval");
        assert_eq!(outcome.verify_status, "blocked_pending_approval");
        assert_eq!(
            outcome.trust_score_after,
            outcome.trust_score_before.saturating_sub(6),
            "trust penalty for blocked should be -6"
        );
    }

    #[test]
    fn guided_session_partial_checkpoints_still_blocked() {
        let recipe_contract = remediation_recipe_contract();
        let logging_contract = structured_logging_contract();
        let recipe = remediation_recipe_fixtures()
            .first()
            .expect("fixture")
            .recipe
            .clone();

        let outcome = run_guided_remediation_session(
            &recipe_contract,
            &logging_contract,
            &recipe,
            &GuidedRemediationSessionRequest {
                run_id: "run-test-partial".to_string(),
                scenario_id: "test-partial-checkpoints".to_string(),
                approved_checkpoints: vec![
                    "checkpoint_diff_review".to_string(),
                    "checkpoint_risk_ack".to_string(),
                ],
                inject_apply_failure: false,
                previous_idempotency_key: None,
            },
        )
        .expect("session");

        assert_eq!(
            outcome.apply_status, "blocked_pending_approval",
            "partial approvals should still block"
        );
    }

    #[test]
    fn guided_session_injected_failure_triggers_rollback_recommended() {
        let recipe_contract = remediation_recipe_contract();
        let logging_contract = structured_logging_contract();
        let recipe = remediation_recipe_fixtures()
            .first()
            .expect("fixture")
            .recipe
            .clone();
        let plan = build_guided_remediation_patch_plan(&recipe_contract, &recipe).expect("plan");
        let approvals = plan
            .approval_checkpoints
            .iter()
            .map(|cp| cp.checkpoint_id.clone())
            .collect::<Vec<_>>();

        let outcome = run_guided_remediation_session(
            &recipe_contract,
            &logging_contract,
            &recipe,
            &GuidedRemediationSessionRequest {
                run_id: "run-test-failure".to_string(),
                scenario_id: "test-apply-failure".to_string(),
                approved_checkpoints: approvals,
                inject_apply_failure: true,
                previous_idempotency_key: None,
            },
        )
        .expect("session");

        assert_eq!(outcome.apply_status, "partial_apply_failed");
        assert_eq!(outcome.verify_status, "rollback_recommended");
        assert_eq!(
            outcome.trust_score_after,
            outcome.trust_score_before.saturating_sub(20),
            "trust penalty for injected failure should be -20"
        );
    }

    #[test]
    fn guided_session_idempotency_noop_preserves_trust() {
        let recipe_contract = remediation_recipe_contract();
        let logging_contract = structured_logging_contract();
        let recipe = remediation_recipe_fixtures()
            .first()
            .expect("fixture")
            .recipe
            .clone();
        let plan = build_guided_remediation_patch_plan(&recipe_contract, &recipe).expect("plan");
        let approvals = plan
            .approval_checkpoints
            .iter()
            .map(|cp| cp.checkpoint_id.clone())
            .collect::<Vec<_>>();

        let outcome = run_guided_remediation_session(
            &recipe_contract,
            &logging_contract,
            &recipe,
            &GuidedRemediationSessionRequest {
                run_id: "run-test-idempotent".to_string(),
                scenario_id: "test-idempotent-noop".to_string(),
                approved_checkpoints: approvals,
                inject_apply_failure: false,
                previous_idempotency_key: Some(plan.idempotency_key),
            },
        )
        .expect("session");

        assert_eq!(outcome.apply_status, "idempotent_noop");
        assert_eq!(outcome.verify_status, "verified_noop");
        assert_eq!(
            outcome.trust_score_before, outcome.trust_score_after,
            "idempotent noop must not change trust score"
        );
    }

    #[test]
    fn guided_session_rejects_empty_run_id() {
        let recipe_contract = remediation_recipe_contract();
        let logging_contract = structured_logging_contract();
        let recipe = remediation_recipe_fixtures()
            .first()
            .expect("fixture")
            .recipe
            .clone();

        let err = run_guided_remediation_session(
            &recipe_contract,
            &logging_contract,
            &recipe,
            &GuidedRemediationSessionRequest {
                run_id: String::new(),
                scenario_id: "test-empty-run-id".to_string(),
                approved_checkpoints: vec![],
                inject_apply_failure: false,
                previous_idempotency_key: None,
            },
        )
        .expect_err("must fail");
        assert!(err.contains("run_id must be non-empty"), "{err}");
    }

    #[test]
    fn guided_session_rejects_empty_scenario_id() {
        let recipe_contract = remediation_recipe_contract();
        let logging_contract = structured_logging_contract();
        let recipe = remediation_recipe_fixtures()
            .first()
            .expect("fixture")
            .recipe
            .clone();

        let err = run_guided_remediation_session(
            &recipe_contract,
            &logging_contract,
            &recipe,
            &GuidedRemediationSessionRequest {
                run_id: "run-test-empty-scenario".to_string(),
                scenario_id: "   ".to_string(),
                approved_checkpoints: vec![],
                inject_apply_failure: false,
                previous_idempotency_key: None,
            },
        )
        .expect_err("must fail");
        assert!(err.contains("scenario_id must be non-empty"), "{err}");
    }

    #[test]
    fn guided_session_smoke_is_deterministic_and_covers_both_paths() {
        let recipe_contract = remediation_recipe_contract();
        let logging_contract = structured_logging_contract();

        let first = run_guided_remediation_session_smoke(&recipe_contract, &logging_contract)
            .expect("smoke1");
        let second = run_guided_remediation_session_smoke(&recipe_contract, &logging_contract)
            .expect("smoke2");
        assert_eq!(first, second, "smoke must be deterministic");
        assert_eq!(
            first.len(),
            2,
            "smoke must cover success and failure scenarios"
        );

        let success = first
            .iter()
            .find(|o| o.apply_status == "applied")
            .expect("must include success scenario");
        assert_eq!(success.verify_status, "verified");

        let failure = first
            .iter()
            .find(|o| o.apply_status == "partial_apply_failed")
            .expect("must include failure scenario");
        assert_eq!(failure.verify_status, "rollback_recommended");
    }

    #[test]
    fn guided_session_smoke_event_streams_validate() {
        let recipe_contract = remediation_recipe_contract();
        let logging_contract = structured_logging_contract();

        let outcomes = run_guided_remediation_session_smoke(&recipe_contract, &logging_contract)
            .expect("smoke");
        for outcome in &outcomes {
            validate_structured_logging_event_stream(&logging_contract, &outcome.events)
                .expect("each outcome's event stream must validate");
            assert_eq!(
                outcome.events.len(),
                4,
                "each outcome must emit exactly 4 events (preview, apply, verify, summary)"
            );
        }
    }

    #[test]
    fn guided_session_success_verify_event_has_no_unresolved_risk() {
        let recipe_contract = remediation_recipe_contract();
        let logging_contract = structured_logging_contract();
        let recipe = remediation_recipe_fixtures()
            .first()
            .expect("fixture")
            .recipe
            .clone();
        let plan = build_guided_remediation_patch_plan(&recipe_contract, &recipe).expect("plan");
        let approvals = plan
            .approval_checkpoints
            .iter()
            .map(|cp| cp.checkpoint_id.clone())
            .collect::<Vec<_>>();

        let outcome = run_guided_remediation_session(
            &recipe_contract,
            &logging_contract,
            &recipe,
            &GuidedRemediationSessionRequest {
                run_id: "run-test-risk-flags".to_string(),
                scenario_id: "test-risk-flag-check".to_string(),
                approved_checkpoints: approvals,
                inject_apply_failure: false,
                previous_idempotency_key: None,
            },
        )
        .expect("session");

        let verify_event = outcome
            .events
            .iter()
            .find(|e| e.event_kind == "remediation_verify")
            .expect("must have verify event");
        assert_eq!(
            verify_event
                .fields
                .get("unresolved_risk_flags")
                .map(String::as_str),
            Some("none"),
            "verified outcome should have no unresolved risk flags"
        );
    }

    #[test]
    fn guided_session_failure_verify_event_preserves_risk_flags() {
        let recipe_contract = remediation_recipe_contract();
        let logging_contract = structured_logging_contract();
        let recipe = remediation_recipe_fixtures()
            .first()
            .expect("fixture")
            .recipe
            .clone();
        let plan = build_guided_remediation_patch_plan(&recipe_contract, &recipe).expect("plan");
        let approvals = plan
            .approval_checkpoints
            .iter()
            .map(|cp| cp.checkpoint_id.clone())
            .collect::<Vec<_>>();

        let outcome = run_guided_remediation_session(
            &recipe_contract,
            &logging_contract,
            &recipe,
            &GuidedRemediationSessionRequest {
                run_id: "run-test-fail-risk".to_string(),
                scenario_id: "test-fail-risk-flags".to_string(),
                approved_checkpoints: approvals,
                inject_apply_failure: true,
                previous_idempotency_key: None,
            },
        )
        .expect("session");

        let verify_event = outcome
            .events
            .iter()
            .find(|e| e.event_kind == "remediation_verify")
            .expect("must have verify event");
        let flags = verify_event
            .fields
            .get("unresolved_risk_flags")
            .expect("must have unresolved_risk_flags field");
        assert_ne!(
            flags, "none",
            "failed outcome should preserve risk flags, got: {flags}"
        );
    }

    #[test]
    fn guided_session_trust_score_capped_at_100() {
        let contract = remediation_recipe_contract();
        let logging_contract = structured_logging_contract();
        let mut recipe = remediation_recipe_fixtures()
            .first()
            .expect("fixture")
            .recipe
            .clone();
        for input in &mut recipe.confidence_inputs {
            input.score = 99;
        }
        let plan = build_guided_remediation_patch_plan(&contract, &recipe).expect("plan");
        let approvals = plan
            .approval_checkpoints
            .iter()
            .map(|cp| cp.checkpoint_id.clone())
            .collect::<Vec<_>>();

        let outcome = run_guided_remediation_session(
            &contract,
            &logging_contract,
            &recipe,
            &GuidedRemediationSessionRequest {
                run_id: "run-test-cap".to_string(),
                scenario_id: "test-trust-cap".to_string(),
                approved_checkpoints: approvals,
                inject_apply_failure: false,
                previous_idempotency_key: None,
            },
        )
        .expect("session");

        assert!(
            outcome.trust_score_after <= 100,
            "trust score must cap at 100, got {}",
            outcome.trust_score_after
        );
    }

    // ── end guided remediation pipeline tests ─────────────────────────

    #[test]
    fn execution_adapter_contract_validates() {
        let contract = execution_adapter_contract();
        validate_execution_adapter_contract(&contract).expect("valid execution adapter contract");
    }

    #[test]
    fn execution_adapter_contract_is_deterministic() {
        let first = execution_adapter_contract();
        let second = execution_adapter_contract();
        assert_eq!(first, second);
    }

    #[test]
    fn execution_adapter_contract_round_trip_json() {
        let contract = execution_adapter_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: ExecutionAdapterContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_execution_adapter_contract(&parsed).expect("parsed contract valid");
    }

    #[test]
    fn execution_adapter_contract_rejects_unsorted_command_classes() {
        let mut contract = execution_adapter_contract();
        contract.command_classes.swap(0, 1);
        let err = validate_execution_adapter_contract(&contract).expect_err("must fail");
        assert!(
            err.contains("command_classes.class_id must be lexically sorted"),
            "{err}"
        );
    }

    #[test]
    fn plan_execution_command_wraps_rch_invocation() {
        let contract = execution_adapter_contract();
        let request = ExecutionAdapterRequest {
            command_id: "cmd-1".to_string(),
            command_class: "cargo_test".to_string(),
            correlation_id: "corr-1".to_string(),
            raw_command: "  cargo   test   -p   asupersync ".to_string(),
            prefer_remote: true,
        };
        let plan = plan_execution_command(&contract, &request, true).expect("plan should build");
        assert_eq!(plan.route, "remote_rch");
        assert_eq!(plan.normalized_command, "cargo test -p asupersync");
        assert_eq!(plan.routed_command, "rch exec -- cargo test -p asupersync");
        assert_eq!(plan.initial_state, "planned");
    }

    #[test]
    fn plan_execution_command_falls_back_when_rch_unavailable() {
        let contract = execution_adapter_contract();
        let request = ExecutionAdapterRequest {
            command_id: "cmd-2".to_string(),
            command_class: "cargo_check".to_string(),
            correlation_id: "corr-2".to_string(),
            raw_command: "cargo check --all-targets".to_string(),
            prefer_remote: true,
        };
        let plan = plan_execution_command(&contract, &request, false).expect("plan should build");
        assert_eq!(plan.route, "local_direct");
        assert_eq!(plan.routed_command, "cargo check --all-targets");
    }

    #[test]
    fn advance_execution_state_supports_cancel_path() {
        let contract = execution_adapter_contract();
        let queued = advance_execution_state(&contract, "planned", "enqueue").expect("enqueue");
        let running = advance_execution_state(&contract, &queued, "start").expect("start");
        let cancel_requested =
            advance_execution_state(&contract, &running, "cancel").expect("cancel");
        let cancelled = advance_execution_state(&contract, &cancel_requested, "cancel_completed")
            .expect("cancel complete");
        assert_eq!(cancelled, "cancelled");
    }

    #[test]
    fn advance_execution_state_rejects_invalid_transition() {
        let contract = execution_adapter_contract();
        let err = advance_execution_state(&contract, "planned", "cancel").expect_err("must fail");
        assert!(err.contains("invalid execution state transition"), "{err}");
    }

    #[test]
    fn scenario_composer_contract_validates() {
        let contract = scenario_composer_contract();
        validate_scenario_composer_contract(&contract).expect("valid scenario composer contract");
    }

    #[test]
    fn scenario_composer_contract_is_deterministic() {
        let first = scenario_composer_contract();
        let second = scenario_composer_contract();
        assert_eq!(first, second);
    }

    #[test]
    fn scenario_composer_contract_round_trip_json() {
        let contract = scenario_composer_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: ScenarioComposerContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_scenario_composer_contract(&parsed).expect("parsed contract valid");
    }

    #[test]
    fn scenario_composer_contract_rejects_unknown_command_class_reference() {
        let mut contract = scenario_composer_contract();
        contract.scenario_templates[0]
            .required_command_classes
            .push("unknown_command_class".to_string());
        contract.scenario_templates[0]
            .required_command_classes
            .sort();
        let err = validate_scenario_composer_contract(&contract).expect_err("must fail");
        assert!(err.contains("references unknown command class"), "{err}");
    }

    #[test]
    fn compose_scenario_run_uses_defaults() {
        let contract = scenario_composer_contract();
        let request = ScenarioRunRequest {
            run_id: "run-happy".to_string(),
            template_id: "scenario_happy_path_smoke".to_string(),
            correlation_id: "corr-happy".to_string(),
            seed: String::new(),
            priority_override: None,
            requested_by: "doctor_cli".to_string(),
        };
        let entry = compose_scenario_run(&contract, &request).expect("compose should succeed");
        assert_eq!(entry.queue_id, "queue-run-happy");
        assert_eq!(entry.priority, 120);
        assert_eq!(entry.state, "queued");
    }

    #[test]
    fn orchestration_state_machine_requires_seed_for_replay_template() {
        let contract = scenario_composer_contract();
        let request = ScenarioRunRequest {
            run_id: "run-no-seed".to_string(),
            template_id: "scenario_cancel_recovery".to_string(),
            correlation_id: "corr-no-seed".to_string(),
            seed: String::new(),
            priority_override: None,
            requested_by: "doctor_cli".to_string(),
        };
        let err = compose_scenario_run(&contract, &request).expect_err("must fail");
        assert!(
            err.contains("seed must be non-empty for templates requiring replay seed"),
            "{err}"
        );
    }

    #[test]
    fn orchestration_state_machine_trims_seed_and_run_id_for_lineage() {
        let contract = scenario_composer_contract();
        let request = ScenarioRunRequest {
            run_id: " run-trim ".to_string(),
            template_id: "scenario_cancel_recovery".to_string(),
            correlation_id: "corr-trim".to_string(),
            seed: " seed-77 ".to_string(),
            priority_override: None,
            requested_by: "doctor_cli".to_string(),
        };
        let entry = compose_scenario_run(&contract, &request).expect("compose should succeed");
        assert_eq!(entry.queue_id, "queue-run-trim");
        assert_eq!(entry.run_id, "run-trim");
        assert_eq!(entry.seed, "seed-77");
    }

    #[test]
    fn build_scenario_run_queue_orders_by_priority_then_run_id() {
        let contract = scenario_composer_contract();
        let requests = vec![
            ScenarioRunRequest {
                run_id: "run-b".to_string(),
                template_id: "scenario_happy_path_smoke".to_string(),
                correlation_id: "corr-b".to_string(),
                seed: String::new(),
                priority_override: Some(120),
                requested_by: "doctor_cli".to_string(),
            },
            ScenarioRunRequest {
                run_id: "run-a".to_string(),
                template_id: "scenario_happy_path_smoke".to_string(),
                correlation_id: "corr-a".to_string(),
                seed: String::new(),
                priority_override: Some(220),
                requested_by: "doctor_cli".to_string(),
            },
            ScenarioRunRequest {
                run_id: "run-c".to_string(),
                template_id: "scenario_happy_path_smoke".to_string(),
                correlation_id: "corr-c".to_string(),
                seed: String::new(),
                priority_override: Some(220),
                requested_by: "doctor_cli".to_string(),
            },
        ];
        let queue = build_scenario_run_queue(&contract, &requests).expect("queue should build");
        let order = queue
            .iter()
            .map(|entry| entry.run_id.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            order,
            vec![
                "run-a".to_string(),
                "run-c".to_string(),
                "run-b".to_string()
            ]
        );
    }

    #[test]
    fn build_scenario_run_queue_rejects_queue_overflow() {
        let mut contract = scenario_composer_contract();
        contract.queue_policy.max_queue_depth = 1;
        contract.queue_policy.max_concurrent_runs = 1;

        let requests = vec![
            ScenarioRunRequest {
                run_id: "run-one".to_string(),
                template_id: "scenario_happy_path_smoke".to_string(),
                correlation_id: "corr-one".to_string(),
                seed: String::new(),
                priority_override: None,
                requested_by: "doctor_cli".to_string(),
            },
            ScenarioRunRequest {
                run_id: "run-two".to_string(),
                template_id: "scenario_happy_path_smoke".to_string(),
                correlation_id: "corr-two".to_string(),
                seed: String::new(),
                priority_override: None,
                requested_by: "doctor_cli".to_string(),
            },
        ];
        let err = build_scenario_run_queue(&contract, &requests).expect_err("must fail");
        assert!(err.contains("queue_full"), "{err}");
    }

    #[test]
    fn dispatch_scenario_run_queue_respects_max_concurrency() {
        let contract = scenario_composer_contract();
        let requests = vec![
            ScenarioRunRequest {
                run_id: "run-1".to_string(),
                template_id: "scenario_regression_bundle".to_string(),
                correlation_id: "corr-1".to_string(),
                seed: "seed-1".to_string(),
                priority_override: None,
                requested_by: "doctor_cli".to_string(),
            },
            ScenarioRunRequest {
                run_id: "run-2".to_string(),
                template_id: "scenario_cancel_recovery".to_string(),
                correlation_id: "corr-2".to_string(),
                seed: "seed-2".to_string(),
                priority_override: None,
                requested_by: "doctor_cli".to_string(),
            },
            ScenarioRunRequest {
                run_id: "run-3".to_string(),
                template_id: "scenario_happy_path_smoke".to_string(),
                correlation_id: "corr-3".to_string(),
                seed: String::new(),
                priority_override: None,
                requested_by: "doctor_cli".to_string(),
            },
        ];
        let queue = build_scenario_run_queue(&contract, &requests).expect("queue should build");
        let dispatched = dispatch_scenario_run_queue(&contract, &queue).expect("dispatch works");
        let running = dispatched
            .iter()
            .filter(|entry| entry.state == "running")
            .count();
        assert_eq!(running, 2);
    }

    #[test]
    fn orchestration_state_machine_dispatch_is_deterministic_and_preserves_entries() {
        let contract = scenario_composer_contract();
        let requests = vec![
            ScenarioRunRequest {
                run_id: "run-c".to_string(),
                template_id: "scenario_happy_path_smoke".to_string(),
                correlation_id: "corr-c".to_string(),
                seed: String::new(),
                priority_override: Some(180),
                requested_by: "doctor_cli".to_string(),
            },
            ScenarioRunRequest {
                run_id: "run-a".to_string(),
                template_id: "scenario_cancel_recovery".to_string(),
                correlation_id: "corr-a".to_string(),
                seed: "seed-a".to_string(),
                priority_override: Some(220),
                requested_by: "doctor_cli".to_string(),
            },
            ScenarioRunRequest {
                run_id: "run-d".to_string(),
                template_id: "scenario_happy_path_smoke".to_string(),
                correlation_id: "corr-d".to_string(),
                seed: String::new(),
                priority_override: Some(120),
                requested_by: "doctor_cli".to_string(),
            },
            ScenarioRunRequest {
                run_id: "run-b".to_string(),
                template_id: "scenario_regression_bundle".to_string(),
                correlation_id: "corr-b".to_string(),
                seed: "seed-b".to_string(),
                priority_override: Some(220),
                requested_by: "doctor_cli".to_string(),
            },
        ];
        let queue = build_scenario_run_queue(&contract, &requests).expect("queue should build");
        let first = dispatch_scenario_run_queue(&contract, &queue).expect("first dispatch");
        let second = dispatch_scenario_run_queue(&contract, &queue).expect("second dispatch");

        assert_eq!(first, second, "dispatch order must be deterministic");
        assert_eq!(
            first.len(),
            requests.len(),
            "dispatch must preserve entries"
        );

        let ordered = first
            .iter()
            .map(|entry| entry.run_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ordered, vec!["run-a", "run-b", "run-c", "run-d"]);
        assert_eq!(
            first
                .iter()
                .filter(|entry| entry.state == "running")
                .count(),
            usize::from(contract.queue_policy.max_concurrent_runs)
        );
        assert!(
            first
                .iter()
                .all(|entry| entry.state == "running" || entry.state == "queued")
        );
    }

    #[test]
    fn orchestration_state_machine_transition_matrix_matches_contract() {
        let contract = execution_adapter_contract();
        let states = [
            "planned",
            "queued",
            "running",
            "cancel_requested",
            "succeeded",
            "failed",
            "cancelled",
        ];
        let triggers = [
            "enqueue",
            "start",
            "cancel",
            "process_exit_zero",
            "process_exit_nonzero",
            "cancel_completed",
            "cancel_timeout",
        ];

        let allowed = contract
            .state_transitions
            .iter()
            .map(|transition| {
                (
                    (transition.from_state.as_str(), transition.trigger.as_str()),
                    transition.to_state.as_str(),
                )
            })
            .collect::<BTreeMap<_, _>>();

        for state in states {
            for trigger in triggers {
                let next = advance_execution_state(&contract, state, trigger);
                if let Some(expected) = allowed.get(&(state, trigger)) {
                    assert_eq!(next.expect("valid transition"), *expected);
                } else {
                    let err = next.expect_err("transition should be rejected");
                    assert!(err.contains("invalid execution state transition"), "{err}");
                }
            }
        }
    }

    #[test]
    fn e2e_harness_core_contract_validates() {
        let contract = e2e_harness_core_contract();
        validate_e2e_harness_core_contract(&contract).expect("valid harness contract");
    }

    #[test]
    fn e2e_harness_core_contract_round_trip_json() {
        let contract = e2e_harness_core_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: E2eHarnessCoreContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_e2e_harness_core_contract(&parsed).expect("parsed harness contract valid");
    }

    #[test]
    fn parse_e2e_harness_config_rejects_missing_field() {
        let contract = e2e_harness_core_contract();
        let mut raw = BTreeMap::from([
            ("correlation_id".to_string(), "corr-e2e".to_string()),
            ("expected_outcome".to_string(), "success".to_string()),
            ("requested_by".to_string(), "doctor_cli".to_string()),
            ("run_id".to_string(), "run-e2e".to_string()),
            ("scenario_id".to_string(), "scenario-e2e".to_string()),
            ("script_id".to_string(), "script-smoke".to_string()),
            ("seed".to_string(), "seed-42".to_string()),
            ("timeout_secs".to_string(), "120".to_string()),
        ]);
        raw.remove("seed");
        let err = parse_e2e_harness_config(&contract, &raw).expect_err("must fail");
        assert!(err.contains("missing required config field seed"), "{err}");
    }

    #[test]
    fn parse_e2e_harness_config_parses_valid_input() {
        let contract = e2e_harness_core_contract();
        let raw = BTreeMap::from([
            ("correlation_id".to_string(), "corr-e2e".to_string()),
            ("expected_outcome".to_string(), "success".to_string()),
            ("requested_by".to_string(), "doctor_cli".to_string()),
            ("run_id".to_string(), "run-e2e".to_string()),
            ("scenario_id".to_string(), "scenario-e2e".to_string()),
            ("script_id".to_string(), "script-smoke".to_string()),
            ("seed".to_string(), "seed-42".to_string()),
            ("timeout_secs".to_string(), "120".to_string()),
        ]);
        let parsed = parse_e2e_harness_config(&contract, &raw).expect("parse should succeed");
        assert_eq!(parsed.timeout_secs, 120);
        assert_eq!(parsed.expected_outcome, "success");
    }

    #[test]
    fn propagate_harness_seed_is_deterministic() {
        let first = propagate_harness_seed("seed-42", "stage-bootstrap").expect("first seed");
        let second = propagate_harness_seed("seed-42", "stage-bootstrap").expect("second seed");
        assert_eq!(first, second);
        assert_eq!(first, "seed-42-stage-bootstrap");
    }

    #[test]
    fn build_e2e_harness_transcript_is_deterministic() {
        let contract = e2e_harness_core_contract();
        let raw = BTreeMap::from([
            ("correlation_id".to_string(), "corr-e2e".to_string()),
            ("expected_outcome".to_string(), "success".to_string()),
            ("requested_by".to_string(), "doctor_cli".to_string()),
            ("run_id".to_string(), "run-e2e".to_string()),
            ("scenario_id".to_string(), "scenario-e2e".to_string()),
            ("script_id".to_string(), "script-smoke".to_string()),
            ("seed".to_string(), "seed-42".to_string()),
            ("timeout_secs".to_string(), "120".to_string()),
        ]);
        let config = parse_e2e_harness_config(&contract, &raw).expect("parse");
        let stages = vec![
            "stage-bootstrap".to_string(),
            "stage-run".to_string(),
            "stage-verify".to_string(),
        ];
        let first =
            build_e2e_harness_transcript(&contract, &config, &stages).expect("first transcript");
        let second =
            build_e2e_harness_transcript(&contract, &config, &stages).expect("second transcript");
        assert_eq!(first, second);
        assert_eq!(first.events[0].state, "started");
        assert_eq!(first.events[2].state, "completed");
    }

    #[test]
    fn build_e2e_harness_transcript_rejects_invalid_stage() {
        let contract = e2e_harness_core_contract();
        let raw = BTreeMap::from([
            ("correlation_id".to_string(), "corr-e2e".to_string()),
            ("expected_outcome".to_string(), "success".to_string()),
            ("requested_by".to_string(), "doctor_cli".to_string()),
            ("run_id".to_string(), "run-e2e".to_string()),
            ("scenario_id".to_string(), "scenario-e2e".to_string()),
            ("script_id".to_string(), "script-smoke".to_string()),
            ("seed".to_string(), "seed-42".to_string()),
            ("timeout_secs".to_string(), "120".to_string()),
        ]);
        let config = parse_e2e_harness_config(&contract, &raw).expect("parse");
        let stages = vec!["stage bootstrap".to_string()];
        let err = build_e2e_harness_transcript(&contract, &config, &stages).expect_err("must fail");
        assert!(err.contains("must be slug-like"), "{err}");
    }

    #[test]
    fn orchestration_state_machine_cancelled_transcript_terminal_state() {
        let contract = e2e_harness_core_contract();
        let raw = BTreeMap::from([
            ("correlation_id".to_string(), "corr-e2e".to_string()),
            ("expected_outcome".to_string(), "cancelled".to_string()),
            ("requested_by".to_string(), "doctor_cli".to_string()),
            ("run_id".to_string(), "run-cancel".to_string()),
            ("scenario_id".to_string(), "scenario-cancel".to_string()),
            ("script_id".to_string(), "script-cancel".to_string()),
            ("seed".to_string(), "seed-77".to_string()),
            ("timeout_secs".to_string(), "120".to_string()),
        ]);
        let config = parse_e2e_harness_config(&contract, &raw).expect("parse");
        let stages = vec![
            "stage-bootstrap".to_string(),
            "stage-run".to_string(),
            "stage-cleanup".to_string(),
        ];
        let transcript =
            build_e2e_harness_transcript(&contract, &config, &stages).expect("transcript");

        assert_eq!(transcript.events[0].state, "started");
        assert_eq!(transcript.events[1].state, "running");
        assert_eq!(transcript.events[2].state, "cancelled");
        assert_eq!(transcript.events[2].outcome_class, "cancelled");

        let seeds = transcript
            .events
            .iter()
            .map(|event| event.propagated_seed.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(seeds.len(), stages.len(), "stage seeds must remain unique");
    }

    #[test]
    fn build_e2e_harness_artifact_index_is_lexical_and_stable() {
        let contract = e2e_harness_core_contract();
        let raw = BTreeMap::from([
            ("correlation_id".to_string(), "corr-e2e".to_string()),
            ("expected_outcome".to_string(), "success".to_string()),
            ("requested_by".to_string(), "doctor_cli".to_string()),
            ("run_id".to_string(), "run-e2e".to_string()),
            ("scenario_id".to_string(), "scenario-e2e".to_string()),
            ("script_id".to_string(), "script-smoke".to_string()),
            ("seed".to_string(), "seed-42".to_string()),
            ("timeout_secs".to_string(), "120".to_string()),
        ]);
        let config = parse_e2e_harness_config(&contract, &raw).expect("parse");
        let stages = vec!["stage-bootstrap".to_string(), "stage-verify".to_string()];
        let transcript =
            build_e2e_harness_transcript(&contract, &config, &stages).expect("transcript");
        let index = build_e2e_harness_artifact_index(&contract, &transcript).expect("index");
        let ids = index
            .iter()
            .map(|entry| entry.artifact_id.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec![
                "scenario-e2e-structured-log".to_string(),
                "scenario-e2e-summary".to_string(),
                "scenario-e2e-transcript".to_string(),
            ]
        );
    }

    #[test]
    fn doctor_scenario_coverage_packs_contract_validates() {
        let contract = doctor_scenario_coverage_packs_contract();
        validate_doctor_scenario_coverage_packs_contract(&contract).expect("valid contract");
    }

    #[test]
    fn doctor_scenario_coverage_packs_contract_round_trip_json() {
        let contract = doctor_scenario_coverage_packs_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: DoctorScenarioCoveragePacksContract =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_doctor_scenario_coverage_packs_contract(&parsed).expect("parsed contract valid");
    }

    #[test]
    fn select_doctor_scenario_coverage_packs_filters_variants() {
        let contract = doctor_scenario_coverage_packs_contract();
        let cancellation =
            select_doctor_scenario_coverage_packs(&contract, "cancellation").expect("select");
        assert_eq!(cancellation.len(), 1);
        assert_eq!(cancellation[0].workflow_variant, "cancellation");

        let all = select_doctor_scenario_coverage_packs(&contract, "all").expect("select");
        let variants = all
            .iter()
            .map(|pack| pack.workflow_variant.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            variants,
            BTreeSet::from([
                "cancellation".to_string(),
                "degraded_dependency".to_string(),
                "recovery".to_string(),
                "retry".to_string(),
            ])
        );
    }

    #[test]
    fn doctor_scenario_coverage_pack_smoke_report_is_deterministic() {
        let contract = doctor_scenario_coverage_packs_contract();
        let first = build_doctor_scenario_coverage_pack_smoke_report(&contract, "all", "seed-4242")
            .expect("first");
        let second =
            build_doctor_scenario_coverage_pack_smoke_report(&contract, "all", "seed-4242")
                .expect("second");
        assert_eq!(first, second);
        assert_eq!(first.runs.len(), 4);
        assert_eq!(
            first
                .runs
                .iter()
                .map(|run| run.workflow_variant.clone())
                .collect::<Vec<_>>(),
            vec![
                "cancellation".to_string(),
                "degraded_dependency".to_string(),
                "recovery".to_string(),
                "retry".to_string(),
            ]
        );
    }

    #[test]
    fn doctor_scenario_coverage_pack_smoke_report_aligns_terminal_outcomes() {
        let contract = doctor_scenario_coverage_packs_contract();
        let report = build_doctor_scenario_coverage_pack_smoke_report(&contract, "all", "seed-900")
            .expect("report");
        for run in &report.runs {
            let expected_terminal =
                expected_terminal_state_for_outcome(&run.expected_outcome).expect("mapping");
            assert_eq!(
                run.terminal_state, expected_terminal,
                "pack {}",
                run.pack_id
            );
            assert_eq!(run.status, "passed");
            assert_eq!(
                run.artifact_index
                    .iter()
                    .map(|entry| entry.artifact_class.clone())
                    .collect::<Vec<_>>(),
                vec![
                    "structured_log".to_string(),
                    "summary".to_string(),
                    "transcript".to_string(),
                ]
            );
            assert!(
                run.structured_log_summary
                    .snapshot_path
                    .starts_with("artifacts/"),
                "snapshot path should remain canonical"
            );
            assert!(
                run.structured_log_summary
                    .metrics_path
                    .starts_with("artifacts/"),
                "metrics path should remain canonical"
            );
            assert!(
                run.structured_log_summary
                    .replay_metadata_path
                    .starts_with("artifacts/"),
                "replay metadata path should remain canonical"
            );
        }
    }

    #[test]
    fn doctor_scenario_coverage_pack_visual_harness_manifest_is_complete() {
        let contract = doctor_scenario_coverage_packs_contract();
        let report =
            build_doctor_scenario_coverage_pack_smoke_report(&contract, "all", "seed-visual")
                .expect("report");
        for run in &report.runs {
            assert_eq!(
                run.artifact_manifest.schema_version,
                DOCTOR_VISUAL_HARNESS_MANIFEST_VERSION
            );
            assert_eq!(run.artifact_manifest.run_id, run.transcript.run_id);
            assert_eq!(
                run.artifact_manifest.scenario_id,
                run.transcript.scenario_id
            );
            assert_eq!(
                run.visual_snapshot.viewport_width,
                DEFAULT_VISUAL_VIEWPORT_WIDTH
            );
            assert_eq!(
                run.visual_snapshot.viewport_height,
                DEFAULT_VISUAL_VIEWPORT_HEIGHT
            );
            assert!(
                run.visual_snapshot.stage_digest.starts_with("len:"),
                "stage digest should use canonical content_digest formatting"
            );

            let classes = run
                .artifact_manifest
                .records
                .iter()
                .map(|record| record.artifact_class.clone())
                .collect::<BTreeSet<_>>();
            assert_eq!(
                classes,
                BTreeSet::from([
                    "metrics".to_string(),
                    "replay_metadata".to_string(),
                    "snapshot".to_string(),
                    "structured_log".to_string(),
                    "summary".to_string(),
                    "transcript".to_string(),
                ])
            );

            for record in &run.artifact_manifest.records {
                assert!(
                    record.artifact_path.starts_with("artifacts/"),
                    "artifact paths must stay under artifacts/: {}",
                    record.artifact_id
                );
                assert!(
                    matches!(record.retention_class.as_str(), "hot" | "warm"),
                    "retention class must stay canonical"
                );
                let mut linked = record.linked_artifacts.clone();
                let mut sorted = linked.clone();
                sorted.sort();
                sorted.dedup();
                assert_eq!(linked, sorted, "linked artifacts must be lexical+unique");
                linked.clear();
            }
        }
    }

    #[test]
    fn doctor_stress_soak_contract_validates() {
        let contract = doctor_stress_soak_contract();
        validate_doctor_stress_soak_contract(&contract).expect("valid stress/soak contract");
    }

    #[test]
    fn doctor_stress_soak_contract_round_trip_json() {
        let contract = doctor_stress_soak_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: DoctorStressSoakContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_doctor_stress_soak_contract(&parsed).expect("parsed contract valid");
    }

    #[test]
    fn doctor_stress_soak_smoke_report_is_deterministic() {
        let contract = doctor_stress_soak_contract();
        let first =
            build_doctor_stress_soak_smoke_report(&contract, "soak", "seed-4242").expect("first");
        let second =
            build_doctor_stress_soak_smoke_report(&contract, "soak", "seed-4242").expect("second");
        assert_eq!(first, second);
        assert_eq!(first.schema_version, "doctor-stress-soak-report-v1");
    }

    #[test]
    fn doctor_stress_soak_profile_controls_checkpoint_depth() {
        let contract = doctor_stress_soak_contract();
        let fast = build_doctor_stress_soak_smoke_report(&contract, "fast", "seed-100")
            .expect("fast report");
        let soak = build_doctor_stress_soak_smoke_report(&contract, "soak", "seed-100")
            .expect("soak report");

        let fast_first = fast.runs.first().expect("fast run");
        let soak_first = soak.runs.first().expect("soak run");
        assert!(
            soak_first.checkpoint_count > fast_first.checkpoint_count,
            "soak profile must record more checkpoints than fast profile"
        );
        assert!(soak_first.duration_steps > fast_first.duration_steps);
    }

    #[test]
    fn doctor_stress_soak_smoke_enforces_sustained_budget_conformance() {
        let contract = doctor_stress_soak_contract();
        let report =
            build_doctor_stress_soak_smoke_report(&contract, "soak", "seed-909").expect("report");

        assert!(
            report
                .failing_scenarios
                .contains(&"doctor-stress-cancel-recovery-pressure".to_string()),
            "cancel/recovery pressure scenario must emit budget failure"
        );
        assert!(
            report
                .runs
                .iter()
                .any(|run| run.status == "budget_failed" && !run.sustained_budget_pass)
        );
        assert!(
            report
                .runs
                .iter()
                .any(|run| run.status == "passed" && run.sustained_budget_pass)
        );
    }

    #[test]
    fn doctor_stress_soak_failure_output_includes_saturation_trace_and_rerun() {
        let contract = doctor_stress_soak_contract();
        let report =
            build_doctor_stress_soak_smoke_report(&contract, "soak", "seed-5150").expect("report");

        let failed = report
            .runs
            .iter()
            .find(|run| run.status == "budget_failed")
            .expect("must include failed run");
        let failure_output = failed
            .failure_output
            .as_ref()
            .expect("failed run must include failure output");
        assert!(
            !failure_output.saturation_indicators.is_empty(),
            "failure output must include saturation indicators"
        );
        assert!(
            failure_output.trace_correlation.starts_with("trace-"),
            "failure output must include trace correlation"
        );
        assert!(
            failure_output
                .rerun_command
                .contains("asupersync doctor stress-soak-smoke"),
            "failure output must include precise rerun command"
        );
    }

    #[test]
    fn evidence_timeline_contract_validates() {
        let contract = evidence_timeline_contract();
        validate_evidence_timeline_contract(&contract).expect("valid contract");
    }

    #[test]
    fn evidence_timeline_contract_round_trip_json() {
        let contract = evidence_timeline_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: EvidenceTimelineContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_evidence_timeline_contract(&parsed).expect("parsed contract valid");
    }

    #[test]
    fn build_evidence_timeline_snapshot_orders_groups_and_filters() {
        let contract = evidence_timeline_contract();
        let timeline_json = r#"[
  {
    "id":"timeline-010",
    "occurred_at":"2026-03-01T10:05:00Z",
    "finding_id":"finding-b",
    "title":"B",
    "severity":"critical",
    "status":"open",
    "outcome_class":"failed",
    "evidence_refs":["evidence-010"],
    "command_refs":["cmd-010"],
    "causal_refs":["timeline-005"]
  },
  {
    "id":"timeline-005",
    "occurred_at":"2026-03-01T10:00:00Z",
    "finding_id":"finding-a",
    "title":"A",
    "severity":"high",
    "status":"resolved",
    "outcome_class":"success",
    "evidence_refs":["evidence-005"],
    "command_refs":["cmd-005"],
    "causal_refs":[]
  },
  {
    "id":"timeline-020",
    "occurred_at":"2026-03-01T10:10:00Z",
    "finding_id":"finding-c",
    "title":"C",
    "severity":"critical",
    "status":"in_progress",
    "outcome_class":"failed",
    "evidence_refs":["evidence-020"],
    "command_refs":["cmd-020"],
    "causal_refs":["timeline-010"]
  }
]"#;

        let all_snapshot = build_evidence_timeline_snapshot(
            &contract,
            timeline_json,
            "chronological_asc",
            "all",
            "severity",
            "primary_panel",
            Some("timeline-010"),
        )
        .expect("snapshot");
        let all_ids = all_snapshot
            .nodes
            .iter()
            .map(|node| node.node_id.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            all_ids,
            vec![
                "timeline-005".to_string(),
                "timeline-010".to_string(),
                "timeline-020".to_string(),
            ]
        );
        assert_eq!(
            all_snapshot
                .groups
                .iter()
                .map(|group| group.group_key.clone())
                .collect::<Vec<_>>(),
            vec!["critical".to_string(), "high".to_string()]
        );

        let critical_desc_snapshot = build_evidence_timeline_snapshot(
            &contract,
            timeline_json,
            "chronological_desc",
            "critical_only",
            "status",
            "primary_panel",
            Some("timeline-020"),
        )
        .expect("snapshot");
        let filtered_ids = critical_desc_snapshot
            .nodes
            .iter()
            .map(|node| node.node_id.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            filtered_ids,
            vec!["timeline-020".to_string(), "timeline-010".to_string()]
        );
        assert_eq!(
            critical_desc_snapshot
                .groups
                .iter()
                .map(|group| group.group_key.clone())
                .collect::<Vec<_>>(),
            vec!["in_progress".to_string(), "open".to_string()]
        );
    }

    #[test]
    fn build_evidence_timeline_snapshot_emits_missing_link_and_causal_events() {
        let contract = evidence_timeline_contract();
        let timeline_json = r#"{
  "result": [
    {
      "id":"timeline-a",
      "occurred_at":"2026-03-01T12:00:00Z",
      "finding_id":"finding-a",
      "title":"A",
      "severity":"high",
      "status":"open",
      "outcome_class":"failed",
      "evidence_refs":["evidence-a"],
      "command_refs":["cmd-a"],
      "causal_refs":[]
    },
    {
      "id":"timeline-b",
      "occurred_at":"2026-03-01T12:01:00Z",
      "finding_id":"finding-b",
      "title":"B",
      "severity":"critical",
      "status":"in_progress",
      "outcome_class":"failed",
      "evidence_refs":[],
      "command_refs":["cmd-b"],
      "causal_refs":["timeline-a","timeline-missing"]
    }
  ]
}"#;

        let snapshot = build_evidence_timeline_snapshot(
            &contract,
            timeline_json,
            "chronological_asc",
            "all",
            "outcome",
            "evidence_panel",
            Some("timeline-b"),
        )
        .expect("snapshot");

        assert_eq!(snapshot.evidence_panel_node.as_deref(), Some("timeline-b"));
        assert!(
            snapshot.events.iter().any(|event| {
                event.event_kind == "causal_expansion_decision"
                    && event.node_id.as_deref() == Some("timeline-b")
            }),
            "missing causal_expansion_decision event"
        );
        assert!(
            snapshot.events.iter().any(|event| {
                event.event_kind == "missing_link_diagnostic"
                    && event.node_id.as_deref() == Some("timeline-b")
            }),
            "missing missing_link_diagnostic event"
        );
    }

    #[test]
    fn evidence_timeline_keyboard_flow_smoke_is_deterministic() {
        let contract = evidence_timeline_contract();
        let first = run_evidence_timeline_keyboard_flow_smoke(&contract).expect("first smoke");
        let second = run_evidence_timeline_keyboard_flow_smoke(&contract).expect("second smoke");
        assert_eq!(first, second);
        assert_eq!(first.steps.len(), 5);
        assert_eq!(first.steps[1].focused_panel, "primary_panel");
        assert_eq!(
            first.steps[2].selected_node.as_deref(),
            Some("timeline-002")
        );
        assert_eq!(first.steps[3].focused_panel, "evidence_panel");
        assert_eq!(
            first.steps[3].evidence_panel_node.as_deref(),
            Some("timeline-002")
        );
        assert_eq!(first.steps[4].focused_panel, "primary_panel");
        assert!(first.steps[4].evidence_panel_node.is_none());
    }

    #[test]
    fn beads_command_center_contract_validates() {
        let contract = beads_command_center_contract();
        validate_beads_command_center_contract(&contract).expect("valid contract");
    }

    #[test]
    fn beads_command_center_contract_round_trip_json() {
        let contract = beads_command_center_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: BeadsCommandCenterContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_beads_command_center_contract(&parsed).expect("parsed contract valid");
    }

    #[test]
    fn parse_br_ready_items_sorts_by_priority_then_id() {
        let contract = beads_command_center_contract();
        let raw = r#"[
  {"id":"asupersync-2b4jj.5.2","title":"Mail pane","status":"open","priority":2},
  {"id":"asupersync-2b4jj.5.1","title":"Command center","status":"in_progress","priority":2,"assignee":"VioletStone"},
  {"id":"asupersync-2b4jj.2.1","title":"Scanner","status":"open","priority":1}
]"#;
        let parsed = parse_br_ready_items(&contract, raw).expect("parse");
        let ids = parsed
            .iter()
            .map(|item| item.id.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec![
                "asupersync-2b4jj.2.1".to_string(),
                "asupersync-2b4jj.5.1".to_string(),
                "asupersync-2b4jj.5.2".to_string(),
            ]
        );
        assert_eq!(parsed[1].assignee.as_deref(), Some("VioletStone"));
    }

    #[test]
    fn parse_br_blocked_items_handles_string_and_object_blockers() {
        let contract = beads_command_center_contract();
        let raw = r#"[
  {
    "id":"asupersync-2b4jj.5.2",
    "title":"Mail pane",
    "status":"open",
    "priority":2,
    "blocked_by":["asupersync-2b4jj.2.1", {"id":"asupersync-2b4jj.2.1"}, {"id":"asupersync-2b4jj.2.0"}]
  },
  {
    "id":"asupersync-2b4jj.5.3",
    "title":"Franken export",
    "status":"open",
    "priority":1,
    "blocked_by":["asupersync-2b4jj.5.2"]
  }
]"#;
        let parsed = parse_br_blocked_items(&contract, raw).expect("parse");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].id, "asupersync-2b4jj.5.2");
        assert_eq!(
            parsed[0].blocked_by,
            vec![
                "asupersync-2b4jj.2.0".to_string(),
                "asupersync-2b4jj.2.1".to_string(),
            ]
        );
    }

    #[test]
    fn parse_bv_triage_recommendations_sorts_by_score_and_normalizes_reasons() {
        let contract = beads_command_center_contract();
        let raw = r#"{
  "triage": {
    "quick_ref": {
      "top_picks": [
        {
          "id":"asupersync-2b4jj.5.1",
          "title":"Command center",
          "score":0.31,
          "unblocks":3,
          "reasons":["high impact","available","available"]
        },
        {
          "id":"asupersync-2b4jj.5.2",
          "title":"Mail pane",
          "score":0.2,
          "unblocks":2,
          "reasons":["available"]
        }
      ]
    }
  }
}"#;
        let parsed = parse_bv_triage_recommendations(&contract, raw).expect("parse");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].id, "asupersync-2b4jj.5.1");
        assert_eq!(
            parsed[0].reasons,
            vec!["available".to_string(), "high impact".to_string()]
        );
    }

    #[test]
    fn build_beads_command_center_snapshot_filters_and_marks_stale() {
        let contract = beads_command_center_contract();
        let ready_json = r#"[
  {"id":"asupersync-2b4jj.5.1","title":"Command center","status":"open","priority":2},
  {"id":"asupersync-2b4jj.2.1","title":"Scanner","status":"in_progress","priority":1},
  {"id":"asupersync-2b4jj.5.2","title":"Mail pane","status":"open","priority":2}
]"#;
        let blocked_json = r#"[
  {
    "id":"asupersync-2b4jj.5.2",
    "title":"Mail pane",
    "status":"open",
    "priority":2,
    "blocked_by":[{"id":"asupersync-2b4jj.2.1"}]
  }
]"#;
        let triage_json = r#"{
  "triage": {
    "quick_ref": {
      "top_picks": [
        {"id":"asupersync-2b4jj.5.1","title":"Command center","score":0.3,"unblocks":3,"reasons":["available","high impact"]},
        {"id":"asupersync-2b4jj.5.2","title":"Mail pane","score":0.2,"unblocks":2,"reasons":["available"]}
      ]
    }
  }
}"#;

        let snapshot = build_beads_command_center_snapshot(
            &contract,
            ready_json,
            blocked_json,
            triage_json,
            "unblocked_only",
            301,
        )
        .expect("snapshot");
        let ready_ids = snapshot
            .ready_work
            .iter()
            .map(|item| item.id.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            ready_ids,
            vec![
                "asupersync-2b4jj.2.1".to_string(),
                "asupersync-2b4jj.5.1".to_string(),
            ]
        );
        assert!(snapshot.blocked_work.is_empty());
        assert!(snapshot.stale);
        assert!(
            snapshot
                .events
                .iter()
                .any(|event| event.event_kind == "stale_data_detected")
        );
    }

    #[test]
    fn build_beads_command_center_snapshot_tracks_parse_failures() {
        let contract = beads_command_center_contract();
        let ready_json = "{not-json}";
        let blocked_json = "[]";
        let triage_json = r#"{"triage":{"quick_ref":{"top_picks":[]}}}"#;
        let snapshot = build_beads_command_center_snapshot(
            &contract,
            ready_json,
            blocked_json,
            triage_json,
            "all",
            5,
        )
        .expect("snapshot");
        assert_eq!(snapshot.ready_work.len(), 0);
        assert_eq!(snapshot.parse_errors.len(), 1);
        assert!(
            snapshot.parse_errors[0].contains("parse_failure: ready JSON"),
            "{}",
            snapshot.parse_errors[0]
        );
        assert!(
            snapshot
                .events
                .iter()
                .any(|event| event.event_kind == "parse_failure" && event.source == "ready")
        );
    }

    #[test]
    fn build_beads_command_center_snapshot_handles_empty_state() {
        let contract = beads_command_center_contract();
        let ready_json = "[]";
        let blocked_json = "[]";
        let triage_json = r#"{"triage":{"quick_ref":{"top_picks":[]}}}"#;
        let snapshot = build_beads_command_center_snapshot(
            &contract,
            ready_json,
            blocked_json,
            triage_json,
            "all",
            0,
        )
        .expect("snapshot");
        assert_eq!(snapshot.ready_work.len(), 0);
        assert_eq!(snapshot.blocked_work.len(), 0);
        assert_eq!(snapshot.triage.len(), 0);
        assert_eq!(snapshot.parse_errors.len(), 0);
        assert!(!snapshot.stale);
        assert!(
            snapshot
                .events
                .iter()
                .any(|event| event.event_kind == "snapshot_built")
        );
    }

    #[test]
    fn beads_command_center_smoke_is_deterministic() {
        let contract = beads_command_center_contract();
        let first = run_beads_command_center_smoke(&contract).expect("first smoke");
        let second = run_beads_command_center_smoke(&contract).expect("second smoke");
        assert_eq!(first, second);
        assert_eq!(first.ready_work.len(), 3);
        assert_eq!(first.blocked_work.len(), 1);
        assert_eq!(first.triage.len(), 2);
        assert!(!first.stale);
    }

    #[test]
    fn agent_mail_pane_contract_validates() {
        let contract = agent_mail_pane_contract();
        validate_agent_mail_pane_contract(&contract).expect("valid contract");
    }

    #[test]
    fn agent_mail_pane_contract_round_trip_json() {
        let contract = agent_mail_pane_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: AgentMailPaneContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_agent_mail_pane_contract(&parsed).expect("parsed contract valid");
    }

    #[test]
    fn parse_agent_mail_messages_maps_ack_required_variants() {
        let contract = agent_mail_pane_contract();
        let raw = r#"{
  "result": [
    {
      "id": 2449,
      "subject": "Re: coordination",
      "importance": "normal",
      "ack_required": true,
      "created_ts": "2026-02-27T19:14:05.885632+00:00",
      "thread_id": "coord-2026-02-27-blackelk",
      "from": "BlackElk"
    },
    {
      "id": 2506,
      "subject": "Start mail pane",
      "importance": "normal",
      "ack_required": 0,
      "created_ts": "2026-02-27T23:52:19.925466+00:00",
      "thread_id": "asupersync-2b4jj.5.2",
      "from": "VioletStone",
      "delivery_status": "sent"
    }
  ]
}"#;
        let parsed_inbox =
            parse_agent_mail_messages(&contract, raw, "inbox", "inbox").expect("parse");
        assert!(parsed_inbox[0].ack_required);
        assert_eq!(parsed_inbox[0].direction, "inbox");
        assert_eq!(parsed_inbox[0].delivery_status, "received");

        let parsed_outbox =
            parse_agent_mail_messages(&contract, raw, "outbox", "outbox").expect("parse");
        assert!(!parsed_outbox[1].ack_required);
        assert_eq!(parsed_outbox[1].direction, "outbox");
        assert_eq!(parsed_outbox[1].delivery_status, "sent");
    }

    #[test]
    fn parse_agent_mail_messages_rejects_invalid_direction() {
        let contract = agent_mail_pane_contract();
        let raw = r#"{"result":[]}"#;
        let err =
            parse_agent_mail_messages(&contract, raw, "inbox", "sideways").expect_err("must fail");
        assert!(err.contains("direction must be inbox or outbox"));
    }

    #[test]
    fn parse_agent_mail_contacts_sorts_and_handles_optional_fields() {
        let contract = agent_mail_pane_contract();
        let raw = r#"{
  "result": [
    {
      "to":"ZuluAgent",
      "status":"pending",
      "reason":"Need handshake",
      "updated_ts":"2026-02-27T20:00:00+00:00",
      "expires_ts":"2026-03-06T20:00:00+00:00"
    },
    {
      "to":"AlphaAgent",
      "status":"approved",
      "reason":"Already linked",
      "updated_ts":"2026-02-27T19:00:00+00:00",
      "expires_ts":""
    }
  ]
}"#;
        let contacts = parse_agent_mail_contacts(&contract, raw).expect("parse");
        assert_eq!(contacts.len(), 2);
        assert_eq!(contacts[0].peer, "AlphaAgent");
        assert_eq!(contacts[0].expires_ts, None);
        assert_eq!(contacts[1].peer, "ZuluAgent");
        assert_eq!(
            contacts[1].expires_ts.as_deref(),
            Some("2026-03-06T20:00:00+00:00")
        );
    }

    #[test]
    fn build_agent_mail_pane_snapshot_applies_ack_and_thread_filter() {
        let contract = agent_mail_pane_contract();
        let inbox_json = r#"{
  "result": [
    {
      "id": 2449,
      "subject": "Re: coordination",
      "importance": "normal",
      "ack_required": true,
      "created_ts": "2026-02-27T19:14:05.885632+00:00",
      "thread_id": "coord-2026-02-27-blackelk",
      "from": "BlackElk"
    }
  ]
}"#;
        let outbox_json = r#"[
  {
    "id": 2507,
    "subject": "Re: coordination",
    "importance": "normal",
    "ack_required": 0,
    "created_ts": "2026-02-27T23:52:39.925466+00:00",
    "thread_id": "coord-2026-02-27-blackelk",
    "from": "VioletStone",
    "delivery_status": "sent"
  }
]"#;
        let contacts_json = r#"{"result":[{"to":"BlackElk","status":"approved","reason":"coord","updated_ts":"2026-02-27T18:36:16.334889+00:00"}]}"#;

        let snapshot = build_agent_mail_pane_snapshot(
            &contract,
            inbox_json,
            outbox_json,
            contacts_json,
            Some("coord-2026-02-27-blackelk"),
            "thread_only",
            &[2449],
        )
        .expect("snapshot");
        assert_eq!(snapshot.pending_ack_count, 0);
        assert_eq!(snapshot.thread_messages.len(), 2);
        assert!(
            snapshot
                .events
                .iter()
                .any(|event| event.event_kind == "ack_transition" && event.message_id == Some(2449))
        );
    }

    #[test]
    fn build_agent_mail_pane_snapshot_unacked_only_adds_ack_replay_command() {
        let contract = agent_mail_pane_contract();
        let inbox_json = r#"{
  "result": [
    {
      "id": 3001,
      "subject": "Needs ack",
      "importance": "high",
      "ack_required": true,
      "created_ts": "2026-02-27T20:00:00+00:00",
      "from": "BlackElk"
    }
  ]
}"#;
        let outbox_json = "[]";
        let contacts_json = r#"{"result":[]}"#;

        let snapshot = build_agent_mail_pane_snapshot(
            &contract,
            inbox_json,
            outbox_json,
            contacts_json,
            None,
            "unacked_only",
            &[],
        )
        .expect("snapshot");
        assert_eq!(snapshot.pending_ack_count, 1);
        assert!(
            snapshot
                .replay_commands
                .iter()
                .any(|command| command == &contract.acknowledge_command)
        );
        assert!(
            !snapshot
                .replay_commands
                .iter()
                .any(|command| command == &contract.reply_command)
        );
    }

    #[test]
    fn build_agent_mail_pane_snapshot_tracks_parse_failures_and_delivery_failure() {
        let contract = agent_mail_pane_contract();
        let inbox_json = r#"{
  "result": [
    {
      "id": 3001,
      "subject": "Needs ack",
      "importance": "high",
      "ack_required": true,
      "created_ts": "2026-02-27T20:00:00+00:00",
      "thread_id": "thread-1",
      "from": "BlackElk"
    }
  ]
}"#;
        let outbox_json = r#"[
  {
    "id": 4001,
    "subject": "Reply attempt",
    "importance": "normal",
    "ack_required": 0,
    "created_ts": "2026-02-27T20:01:00+00:00",
    "thread_id": "thread-1",
    "from": "VioletStone",
    "delivery_status": "failed"
  }
]"#;
        let invalid_contacts_json = "{not-json}";

        let snapshot = build_agent_mail_pane_snapshot(
            &contract,
            inbox_json,
            outbox_json,
            invalid_contacts_json,
            Some("thread-1"),
            "all",
            &[],
        )
        .expect("snapshot");
        assert_eq!(snapshot.parse_errors.len(), 1);
        assert_eq!(snapshot.pending_ack_count, 1);
        assert!(
            snapshot
                .events
                .iter()
                .any(|event| event.event_kind == "parse_failure" && event.source == "contacts")
        );
        assert!(
            snapshot
                .events
                .iter()
                .any(|event| event.event_kind == "delivery_failure"
                    && event.message_id == Some(4001))
        );
    }

    #[test]
    fn agent_mail_pane_smoke_workflow_is_deterministic() {
        let contract = agent_mail_pane_contract();
        let first = run_agent_mail_pane_smoke(&contract).expect("first smoke");
        let second = run_agent_mail_pane_smoke(&contract).expect("second smoke");
        assert_eq!(first, second);
        assert_eq!(first.steps.len(), 3);
        assert_eq!(first.steps[0].step_id, "fetch");
        assert_eq!(first.steps[0].snapshot.pending_ack_count, 1);
        assert_eq!(first.steps[1].step_id, "ack");
        assert_eq!(first.steps[1].snapshot.pending_ack_count, 0);
        assert_eq!(first.steps[2].step_id, "reply");
        assert_eq!(first.steps[2].snapshot.thread_messages.len(), 2);
        assert!(
            first.steps[2]
                .snapshot
                .events
                .iter()
                .any(|event| event.event_kind == "thread_view_updated")
        );
    }

    #[test]
    fn agent_swarm_status_contract_validates() {
        let contract = agent_swarm_status_contract();
        validate_agent_swarm_status_contract(&contract).expect("valid ASW status contract");
    }

    #[test]
    fn parse_git_short_status_summarizes_dirty_and_ahead() {
        let parsed = parse_git_short_status(
            "## main...origin/main [ahead 2, behind 1]\n M src/cli/doctor/mod.rs\n?? tests/operator_swarm_status_contract.rs\n",
            &["def456".to_string(), "abc123".to_string(), "abc123".to_string()],
        )
        .expect("parse git status");

        assert_eq!(parsed.branch, "main");
        assert_eq!(parsed.upstream.as_deref(), Some("origin/main"));
        assert_eq!(parsed.ahead, 2);
        assert_eq!(parsed.behind, 1);
        assert_eq!(
            parsed.dirty_paths,
            vec![
                "src/cli/doctor/mod.rs".to_string(),
                "tests/operator_swarm_status_contract.rs".to_string(),
            ]
        );
        assert_eq!(
            parsed.unowned_ahead_commits,
            vec!["abc123".to_string(), "def456".to_string()]
        );
    }

    #[test]
    fn agent_swarm_status_smoke_is_deterministic_and_safe() {
        let contract = agent_swarm_status_contract();
        let first = run_agent_swarm_status_smoke(&contract).expect("first swarm status");
        let second = run_agent_swarm_status_smoke(&contract).expect("second swarm status");
        assert_eq!(first, second);
        assert_eq!(first.schema_version, "doctor-agent-swarm-status-v1");
        assert_eq!(first.health_status, "critical");
        assert_eq!(first.readiness_score, 20);
        assert_eq!(first.ready_bead_count, 2);
        assert_eq!(first.blocked_bead_count, 1);
        assert_eq!(first.stale_bead_count, 3);
        assert_eq!(first.reservation_conflict_count, 1);
        assert_eq!(first.proof_frontier_blocker_count, 1);
        assert!(first.active_agents.contains(&"GreenMountain".to_string()));
        assert!(
            first
                .recommendations
                .iter()
                .any(|recommendation| recommendation.action == "fix_first_proof_blocker")
        );

        let joined_recommendations = first
            .recommendations
            .iter()
            .map(|recommendation| recommendation.reason.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in [
            "git reset",
            "git clean",
            "checkout -b",
            "switch -c",
            "worktree",
        ] {
            assert!(
                !joined_recommendations.contains(forbidden),
                "recommendations must not include forbidden operation: {forbidden}"
            );
        }
    }

    #[test]
    fn core_diagnostics_report_contract_validates() {
        let contract = core_diagnostics_report_contract();
        validate_core_diagnostics_report_contract(&contract).expect("valid core report contract");
    }

    #[test]
    fn core_diagnostics_report_contract_round_trip_json() {
        let contract = core_diagnostics_report_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: CoreDiagnosticsReportContract =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_core_diagnostics_report_contract(&parsed).expect("parsed contract valid");
    }

    #[test]
    fn core_diagnostics_report_bundle_is_deterministic_and_valid() {
        let first = core_diagnostics_report_bundle();
        let second = core_diagnostics_report_bundle();
        assert_eq!(first, second);

        validate_core_diagnostics_report_contract(&first.contract).expect("contract valid");
        for fixture in &first.fixtures {
            validate_core_diagnostics_report(&fixture.report, &first.contract)
                .expect("fixture report valid");
        }
    }

    #[test]
    fn core_diagnostics_report_bundle_snapshot() {
        let bundle = core_diagnostics_report_bundle();
        let snapshot = bundle
            .fixtures
            .iter()
            .map(scrub_core_diagnostics_fixture)
            .collect::<Vec<_>>();

        insta::assert_json_snapshot!("core_diagnostics_report_bundle", snapshot);
    }

    #[test]
    fn core_diagnostics_structured_health_report_snapshot() {
        let bundle = core_diagnostics_report_bundle();
        let snapshot = bundle
            .fixtures
            .iter()
            .map(scrub_core_diagnostics_health_fixture)
            .collect::<Vec<_>>();

        let health_statuses = snapshot
            .iter()
            .filter_map(|fixture| {
                fixture
                    .get("health_status")
                    .and_then(serde_json::Value::as_str)
            })
            .collect::<Vec<_>>();
        assert_eq!(health_statuses, vec!["critical", "passing", "degraded"]);

        insta::assert_json_snapshot!("core_diagnostics_structured_health_report", snapshot);
    }

    #[test]
    fn core_diagnostics_report_rejects_unsorted_findings() {
        let contract = core_diagnostics_report_contract();
        let mut fixture = core_diagnostics_report_fixtures()
            .into_iter()
            .find(|candidate| candidate.fixture_id == "baseline_failure_path")
            .expect("fixture exists");
        fixture.report.findings.swap(0, 1);
        let err = validate_core_diagnostics_report(&fixture.report, &contract)
            .expect_err("unsorted findings must fail");
        assert!(err.contains("findings.finding_id"), "{err}");
    }

    #[test]
    fn core_diagnostics_report_smoke_emits_valid_structured_events() {
        let bundle = core_diagnostics_report_bundle();
        let logging_contract = structured_logging_contract();
        let first =
            run_core_diagnostics_report_smoke(&bundle, &logging_contract).expect("smoke events");
        let second =
            run_core_diagnostics_report_smoke(&bundle, &logging_contract).expect("smoke events");
        assert_eq!(first, second);
        validate_structured_logging_event_stream(&logging_contract, &first)
            .expect("structured event stream valid");

        let mut scenario_ids = first
            .iter()
            .filter_map(|event| event.fields.get("scenario_id").cloned())
            .collect::<Vec<_>>();
        scenario_ids.sort();
        scenario_ids.dedup();
        assert_eq!(
            scenario_ids,
            vec![
                "doctor-core-report-failure".to_string(),
                "doctor-core-report-happy".to_string(),
                "doctor-core-report-partial".to_string(),
            ]
        );
    }

    #[test]
    fn advanced_diagnostics_report_extension_contract_validates() {
        let contract = advanced_diagnostics_report_extension_contract();
        validate_advanced_diagnostics_report_extension_contract(&contract)
            .expect("valid extension contract");
    }

    #[test]
    fn advanced_diagnostics_report_extension_contract_round_trip_json() {
        let contract = advanced_diagnostics_report_extension_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: AdvancedDiagnosticsReportExtensionContract =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_advanced_diagnostics_report_extension_contract(&parsed)
            .expect("parsed extension contract valid");
    }

    #[test]
    fn advanced_diagnostics_bundle_is_deterministic_and_valid() {
        let first = advanced_diagnostics_report_bundle();
        let second = advanced_diagnostics_report_bundle();
        assert_eq!(first, second);

        let fixture_ids = first
            .fixtures
            .iter()
            .map(|fixture| fixture.fixture_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            fixture_ids,
            vec![
                "advanced_conflicting_signal_path",
                "advanced_cross_system_mismatch_path",
                "advanced_failure_path",
                "advanced_happy_path",
                "advanced_partial_success_path",
                "advanced_rollback_path",
            ]
        );

        for fixture in &first.fixtures {
            validate_advanced_diagnostics_report_extension(
                &fixture.extension,
                &fixture.core_report,
                &first.extension_contract,
                &first.core_contract,
            )
            .expect("fixture extension should validate");
            validate_advanced_fixture_provenance_assertions(fixture)
                .expect("fixture provenance assertions should validate");
        }
    }

    #[test]
    fn advanced_cross_system_fixture_requires_expected_channels() {
        let bundle = advanced_diagnostics_report_bundle();
        let fixture = bundle
            .fixtures
            .iter()
            .find(|candidate| candidate.fixture_id == "advanced_cross_system_mismatch_path")
            .expect("cross-system fixture exists");

        let channels = fixture
            .extension
            .collaboration_trail
            .iter()
            .map(|entry| entry.channel.as_str())
            .collect::<BTreeSet<_>>();
        assert!(channels.contains("agent_mail"));
        assert!(channels.contains("beads"));
        assert!(channels.contains("frankensuite"));
    }

    #[test]
    fn advanced_provenance_assertions_reject_invalid_message_ref() {
        let bundle = advanced_diagnostics_report_bundle();
        let mut fixture = bundle
            .fixtures
            .iter()
            .find(|candidate| candidate.fixture_id == "advanced_cross_system_mismatch_path")
            .expect("cross-system fixture exists")
            .clone();
        fixture.extension.collaboration_trail[0].message_ref = "invalid-message-ref".to_string();

        let err = validate_advanced_fixture_provenance_assertions(&fixture)
            .expect_err("invalid message ref must fail");
        assert!(err.contains("mail-*"), "{err}");
    }

    #[test]
    fn advanced_partial_success_fixture_requires_mixed_delta_outcomes() {
        let bundle = advanced_diagnostics_report_bundle();
        let mut fixture = bundle
            .fixtures
            .iter()
            .find(|candidate| candidate.fixture_id == "advanced_partial_success_path")
            .expect("partial-success fixture exists")
            .clone();
        for delta in &mut fixture.extension.remediation_deltas {
            delta.delta_outcome = "success".to_string();
        }

        let err = validate_advanced_fixture_provenance_assertions(&fixture)
            .expect_err("all-success deltas must fail partial-success assertion");
        assert!(err.contains("both success and non-success"), "{err}");
    }

    #[test]
    fn advanced_extension_contract_rejects_unknown_taxonomy_class() {
        let mut contract = advanced_diagnostics_report_extension_contract();
        contract
            .taxonomy_mapping
            .class_allowlist
            .push("unknown_taxonomy_class".to_string());
        contract.taxonomy_mapping.class_allowlist.sort();
        let err = validate_advanced_diagnostics_report_extension_contract(&contract)
            .expect_err("unknown taxonomy class must fail");
        assert!(err.contains("unknown_taxonomy_class"), "{err}");
    }

    #[test]
    fn advanced_extension_rejects_base_report_id_mismatch() {
        let bundle = advanced_diagnostics_report_bundle();
        let fixture = bundle.fixtures.first().expect("fixture exists");
        let mut extension = fixture.extension.clone();
        extension.base_report_id = "doctor-report-mismatch".to_string();

        let err = validate_advanced_diagnostics_report_extension(
            &extension,
            &fixture.core_report,
            &bundle.extension_contract,
            &bundle.core_contract,
        )
        .expect_err("mismatched base report id should fail");
        assert!(err.contains("base_report_id"), "{err}");
    }

    #[test]
    fn advanced_diagnostics_report_smoke_emits_valid_structured_events() {
        let bundle = advanced_diagnostics_report_bundle();
        let logging_contract = structured_logging_contract();
        let first =
            run_advanced_diagnostics_report_smoke(&bundle, &logging_contract).expect("smoke");
        let second =
            run_advanced_diagnostics_report_smoke(&bundle, &logging_contract).expect("smoke");
        assert_eq!(first, second);
        validate_structured_logging_event_stream(&logging_contract, &first)
            .expect("structured events valid");

        let mut scenario_ids = first
            .iter()
            .filter_map(|event| event.fields.get("scenario_id").cloned())
            .collect::<Vec<_>>();
        scenario_ids.sort();
        scenario_ids.dedup();
        assert_eq!(
            scenario_ids,
            vec![
                "doctor-core-report-failure".to_string(),
                "doctor-core-report-happy".to_string(),
            ]
        );
    }
