    use super::*;
    use serde_json::json;

    const HASH_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn valid_bundle() -> IncidentBundle {
        IncidentBundle {
            schema_version: INCIDENT_BUNDLE_SCHEMA_VERSION,
            bundle_id: "incident-fixture-accepted".to_string(),
            sources: vec![IncidentSource {
                source_id: "crashpack-main".to_string(),
                kind: IncidentSourceKind::CrashPack,
                artifact_path: Some("artifacts/crashpacks/fixture.json".to_string()),
                content_hash: HASH_A.to_string(),
                content_bytes: 512,
                redaction_status: IncidentRedactionStatus::Redacted,
                payload_snippet: Some("panic after deterministic schedule seed 42".to_string()),
                metadata: BTreeMap::from([("trace_fingerprint".to_string(), json!("0xfeedbeef"))]),
            }],
            command: IncidentCommand {
                program: "rch".to_string(),
                args: vec![
                    "exec".to_string(),
                    "--".to_string(),
                    "cargo".to_string(),
                    "test".to_string(),
                    "-p".to_string(),
                    "asupersync".to_string(),
                ],
                env: vec![IncidentEnvVar {
                    key: "RUSTFLAGS".to_string(),
                    value: "-C debuginfo=0".to_string(),
                }],
                working_dir: ".".to_string(),
            },
            determinism: IncidentDeterminism {
                seed: Some(42),
                schedule_seed: Some(42),
                virtual_time_nanos: Some(0),
                config_hash: HASH_B.to_string(),
                feature_flags: vec!["test-internals".to_string()],
                target_triple: "x86_64-unknown-linux-gnu".to_string(),
            },
            privacy: IncidentPrivacy {
                classification: IncidentPrivacyClass::Internal,
                redaction_status: IncidentRedactionStatus::Redacted,
                redaction_policy_id: "incident-redaction-v1".to_string(),
            },
            provenance: IncidentProvenance {
                capture_id: "support-incident-fixture-accepted".to_string(),
                origin: "support_bundle".to_string(),
                reporter: "operator".to_string(),
                captured_commit: Some("34b057288".to_string()),
                related_bead_id: Some("asupersync-lkygsb.1".to_string()),
            },
            metadata: BTreeMap::from([("scenario".to_string(), json!("accepted"))]),
        }
    }

    #[test]
    fn valid_bundle_is_accepted() {
        let report = valid_bundle().validate();
        assert!(report.is_accepted(), "{report:#?}");
        assert_eq!(report.bundle_id, "incident-fixture-accepted");
    }

    #[test]
    fn malformed_json_is_rejected_before_validation() {
        let parsed = IncidentBundle::from_json("{not-json");
        assert!(parsed.is_err());
    }

    #[test]
    fn missing_required_fields_fail_during_parse_or_validation() {
        let parsed = IncidentBundle::from_json(r#"{"schema_version":1}"#);
        assert!(parsed.is_err());

        let mut bundle = valid_bundle();
        bundle.bundle_id.clear();
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::MissingRequiredField));
    }

    #[test]
    fn schema_version_mismatch_blocks_import() {
        let mut bundle = valid_bundle();
        bundle.schema_version = INCIDENT_BUNDLE_SCHEMA_VERSION + 1;
        let report = bundle.validate();
        assert_eq!(report.verdict, IncidentValidationVerdict::Blocked);
        assert!(report.contains_kind(IncidentValidationIssueKind::UnsupportedSchemaVersion));
    }

    #[test]
    fn duplicate_source_ids_block_import() {
        let mut bundle = valid_bundle();
        bundle.sources.push(bundle.sources[0].clone());
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::DuplicateSourceId));
    }

    #[test]
    fn unknown_source_kind_deserializes_to_typed_blocker() {
        let json = valid_bundle()
            .to_json()
            .expect("valid bundle should serialize")
            .replace("\"crash_pack\"", "\"future_tool_bundle\"");
        let bundle = IncidentBundle::from_json(&json).expect("unknown kind should parse");
        assert!(matches!(
            bundle.sources[0].kind,
            IncidentSourceKind::Unsupported(_)
        ));
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::UnsupportedSourceKind));
    }

    #[test]
    fn malformed_hash_blocks_import() {
        let mut bundle = valid_bundle();
        bundle.sources[0].content_hash = "not-a-hash".to_string();
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::MalformedContentHash));
    }

    #[test]
    fn oversized_fields_block_import() {
        let mut bundle = valid_bundle();
        bundle.sources[0].payload_snippet = Some("x".repeat(MAX_PAYLOAD_SNIPPET_BYTES + 1));
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::OversizedField));
    }

    #[test]
    fn confidential_bundle_without_redaction_blocks_import() {
        let mut bundle = valid_bundle();
        bundle.privacy.classification = IncidentPrivacyClass::Confidential;
        bundle.privacy.redaction_status = IncidentRedactionStatus::NotRequired;
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::RedactionRequiredButMissing));
    }

    #[test]
    fn missing_redaction_policy_blocks_import() {
        let mut bundle = valid_bundle();
        bundle.privacy.redaction_policy_id.clear();
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::MissingRedactionPolicy));
    }

    #[test]
    fn secret_env_var_blocks_import() {
        let mut bundle = valid_bundle();
        bundle.command.env.push(IncidentEnvVar {
            key: "API_TOKEN".to_string(),
            value: "sk-test-123".to_string(),
        });
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::SecretLikeMaterial));
    }

    #[test]
    fn private_host_paths_block_import() {
        let mut bundle = valid_bundle();
        bundle.sources[0].artifact_path = Some("/home/alice/.ssh/id_rsa".to_string());
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::ExternalPath));
    }

    #[test]
    fn secret_payload_snippet_blocks_import_when_not_redacted() {
        let mut bundle = valid_bundle();
        bundle.sources[0].redaction_status = IncidentRedactionStatus::NotRequired;
        bundle.sources[0].payload_snippet = Some("Authorization: Bearer secret-token".to_string());
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::SecretLikeMaterial));
    }

    #[test]
    fn nested_secret_metadata_blocks_import_when_not_redacted() {
        let mut bundle = valid_bundle();
        bundle.privacy.redaction_status = IncidentRedactionStatus::NotRequired;
        bundle.metadata = BTreeMap::from([(
            "headers".to_string(),
            json!({"authorization": "Bearer abc123"}),
        )]);
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::SecretLikeMaterial));
    }

    #[test]
    fn binary_like_payload_blocks_import() {
        let mut bundle = valid_bundle();
        bundle.sources[0].payload_snippet = Some("prefix\0suffix".to_string());
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::BinaryLikePayload));
    }

    #[test]
    fn duplicate_feature_flags_block_import() {
        let mut bundle = valid_bundle();
        bundle
            .determinism
            .feature_flags
            .push("test-internals".to_string());
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::DuplicateFeatureFlag));
    }

    #[test]
    fn fingerprint_is_stable_for_same_bundle() {
        let bundle = valid_bundle();
        assert_eq!(bundle.fingerprint(), bundle.clone().fingerprint());
        let json = bundle.to_json().expect("valid bundle should serialize");
        let parsed = IncidentBundle::from_json(&json).expect("serialized bundle should parse");
        assert_eq!(bundle.fingerprint(), parsed.fingerprint());
    }

    #[test]
    fn imports_valid_crashpack_bundle_to_replay_package() {
        let report = valid_bundle().import_replay_package();
        assert!(report.is_imported(), "{report:#?}");
        let package = report.package.expect("valid import emits package");
        assert_eq!(
            package.schema_version,
            INCIDENT_REPLAY_PACKAGE_SCHEMA_VERSION
        );
        assert_eq!(package.bundle_id, "incident-fixture-accepted");
        assert_eq!(package.sources[0].role, IncidentReplaySourceRole::CrashPack);
        assert_eq!(package.trace_metadata.seed, 42);
        assert_eq!(package.trace_metadata.recorded_at, 0);
        assert_eq!(package.canonicalization.trace_fingerprints, ["0xfeedbeef"]);
    }

    #[test]
    fn imports_required_source_kinds_without_mock_downgrade() {
        for (kind, role) in [
            (
                IncidentSourceKind::CrashPack,
                IncidentReplaySourceRole::CrashPack,
            ),
            (
                IncidentSourceKind::TraceLog,
                IncidentReplaySourceRole::TraceLog,
            ),
            (
                IncidentSourceKind::RchProofFailure,
                IncidentReplaySourceRole::RchProofFailure,
            ),
            (
                IncidentSourceKind::ReadmeClaimFailure,
                IncidentReplaySourceRole::ReadmeClaimFailure,
            ),
        ] {
            let mut bundle = valid_bundle();
            bundle.sources[0].kind = kind;
            bundle.sources[0].source_id = role.as_str().to_string();
            let content_hash = bundle.sources[0].content_hash.clone();
            bundle.sources[0]
                .metadata
                .insert("observed_content_hash".to_string(), json!(content_hash));
            let report = bundle.import_replay_package();
            assert!(report.is_imported(), "{role:?}: {report:#?}");
            let package = report.package.expect("package emitted");
            assert_eq!(package.sources[0].role, role);
        }
    }

    #[test]
    fn malformed_bundle_json_returns_malformed_import_report() {
        let report = import_incident_bundle_json("{definitely-not-json");
        assert_eq!(report.verdict, IncidentReplayImportVerdict::Malformed);
        assert!(report.contains_kind(IncidentReplayBlockReasonKind::MalformedJson));
    }

    #[test]
    fn schema_validation_failure_blocks_import() {
        let mut bundle = valid_bundle();
        bundle.schema_version = INCIDENT_BUNDLE_SCHEMA_VERSION + 1;
        let report = bundle.import_replay_package();
        assert_eq!(report.verdict, IncidentReplayImportVerdict::Blocked);
        assert!(report.contains_kind(IncidentReplayBlockReasonKind::ValidationIssue));
    }

    #[test]
    fn missing_source_payload_blocks_import() {
        let mut bundle = valid_bundle();
        bundle.sources[0].artifact_path = None;
        bundle.sources[0].payload_snippet = None;
        bundle.sources[0].metadata.clear();
        bundle.sources[0].content_bytes = 0;
        let report = bundle.import_replay_package();
        assert_eq!(report.verdict, IncidentReplayImportVerdict::Blocked);
        assert!(report.contains_kind(IncidentReplayBlockReasonKind::MissingSourcePayload));
    }

    #[test]
    fn stale_observed_hash_blocks_import() {
        let mut bundle = valid_bundle();
        bundle.sources[0].metadata.insert(
            "observed_content_hash".to_string(),
            json!("sha256:9999999999999999999999999999999999999999999999999999999999999999"),
        );
        let report = bundle.import_replay_package();
        assert_eq!(report.verdict, IncidentReplayImportVerdict::Blocked);
        assert!(report.contains_kind(IncidentReplayBlockReasonKind::StaleContentHash));
    }

    #[test]
    fn redaction_required_blocks_import() {
        let mut bundle = valid_bundle();
        bundle.privacy.classification = IncidentPrivacyClass::Secret;
        bundle.privacy.redaction_status = IncidentRedactionStatus::RequiredButMissing;
        let report = bundle.import_replay_package();
        assert_eq!(report.verdict, IncidentReplayImportVerdict::Blocked);
        assert!(report.contains_kind(IncidentReplayBlockReasonKind::RedactionRequiredButMissing));
    }

    #[test]
    fn package_id_is_stable_for_equivalent_source_order() {
        let mut first = valid_bundle();
        first.sources.push(IncidentSource {
            source_id: "trace-log-main".to_string(),
            kind: IncidentSourceKind::TraceLog,
            artifact_path: Some("artifacts/traces/fixture.ndjson".to_string()),
            content_hash: HASH_B.to_string(),
            content_bytes: 128,
            redaction_status: IncidentRedactionStatus::Redacted,
            payload_snippet: None,
            metadata: BTreeMap::from([("trace_fingerprint".to_string(), json!("0xbead"))]),
        });

        let mut second = first.clone();
        second.sources.reverse();

        let first_package = first
            .import_replay_package()
            .package
            .expect("first import emits package");
        let second_package = second
            .import_replay_package()
            .package
            .expect("second import emits package");

        assert_eq!(first_package.package_id, second_package.package_id);
        assert_eq!(
            first_package.canonicalization.source_order,
            second_package.canonicalization.source_order
        );
    }

    #[test]
    fn replay_package_json_round_trip_is_stable() {
        let package = valid_bundle()
            .import_replay_package()
            .package
            .expect("valid import emits package");
        let json = package.to_json().expect("package serializes");
        let parsed = IncidentReplayPackage::from_json(&json).expect("package parses");
        assert_eq!(package.package_id, parsed.package_id);
        assert_eq!(package, parsed);
    }

    fn two_source_package() -> IncidentReplayPackage {
        let mut bundle = valid_bundle();
        bundle.sources.push(IncidentSource {
            source_id: "trace-log-main".to_string(),
            kind: IncidentSourceKind::TraceLog,
            artifact_path: Some("artifacts/traces/fixture.ndjson".to_string()),
            content_hash: HASH_B.to_string(),
            content_bytes: 128,
            redaction_status: IncidentRedactionStatus::Redacted,
            payload_snippet: None,
            metadata: BTreeMap::from([
                ("trace_fingerprint".to_string(), json!("0xbead")),
                ("observed_content_hash".to_string(), json!(HASH_B)),
            ]),
        });
        bundle
            .import_replay_package()
            .package
            .expect("fixture package imports")
    }

    fn panic_oracle() -> IncidentReplayOracle {
        IncidentReplayOracle {
            kind: IncidentOracleKind::Panic,
            expected_signal: "panic after deterministic schedule seed 42".to_string(),
            stable: true,
            required_source_roles: vec![IncidentReplaySourceRole::CrashPack],
            required_trace_fingerprint: Some("0xfeedbeef".to_string()),
        }
    }

    #[test]
    fn minimizer_preserves_oracle_and_shrinks_sources() {
        let package = two_source_package();
        let report = package.minimize_repro(
            panic_oracle(),
            IncidentReplayMinimizationConfig {
                step_budget: 8,
                shrink_feature_flags: false,
            },
        );

        assert_eq!(report.verdict, IncidentReplayMinimizationVerdict::Minimized);
        let repro = report.repro.expect("minimized repro emitted");
        assert_eq!(repro.retained_sources.len(), 1);
        assert_eq!(
            repro.retained_sources[0].role,
            IncidentReplaySourceRole::CrashPack
        );
        assert_eq!(repro.removed_source_ids, ["trace-log-main"]);
        assert!(repro.summary.minimized_units < repro.summary.original_units);
        assert!(repro.steps.iter().any(|step| step.accepted));
    }

    #[test]
    fn minimizer_is_monotonic_and_records_rejections() {
        let package = two_source_package();
        let report = package.minimize_repro(
            IncidentReplayOracle {
                required_trace_fingerprint: Some("0xbead".to_string()),
                ..panic_oracle()
            },
            IncidentReplayMinimizationConfig {
                step_budget: 8,
                shrink_feature_flags: false,
            },
        );
        let repro = report.repro.expect("repro emitted");

        assert!(
            repro.summary.minimized_units <= repro.summary.original_units,
            "{repro:#?}"
        );
        assert!(repro.steps.iter().any(|step| !step.accepted));
    }

    #[test]
    fn minimizer_reports_budget_exhaustion() {
        let package = two_source_package();
        let report = package.minimize_repro(
            panic_oracle(),
            IncidentReplayMinimizationConfig {
                step_budget: 0,
                shrink_feature_flags: true,
            },
        );

        assert_eq!(
            report.verdict,
            IncidentReplayMinimizationVerdict::BudgetExhausted
        );
        assert!(report.contains_issue(IncidentReplayMinimizationIssueKind::BudgetExhausted));
        assert!(report.steps.iter().any(|step| {
            step.kind == IncidentReplayShrinkStepKind::BudgetExhausted && !step.accepted
        }));
    }

    #[test]
    fn flaky_oracle_is_inconclusive() {
        let package = two_source_package();
        let mut oracle = panic_oracle();
        oracle.stable = false;
        let report = package.minimize_repro(oracle, IncidentReplayMinimizationConfig::default());

        assert_eq!(
            report.verdict,
            IncidentReplayMinimizationVerdict::Inconclusive
        );
        assert!(report.contains_issue(IncidentReplayMinimizationIssueKind::FlakyOracle));
        assert!(report.repro.is_none());
    }

    #[test]
    fn empty_trace_blocks_minimization() {
        let mut package = two_source_package();
        package.sources.clear();
        let report =
            package.minimize_repro(panic_oracle(), IncidentReplayMinimizationConfig::default());

        assert_eq!(report.verdict, IncidentReplayMinimizationVerdict::Blocked);
        assert!(report.contains_issue(IncidentReplayMinimizationIssueKind::EmptyTrace));
    }

    #[test]
    fn single_event_trace_is_already_minimal() {
        let package = valid_bundle()
            .import_replay_package()
            .package
            .expect("single source imports");
        let report = package.minimize_repro(
            panic_oracle(),
            IncidentReplayMinimizationConfig {
                step_budget: 8,
                shrink_feature_flags: false,
            },
        );

        assert_eq!(
            report.verdict,
            IncidentReplayMinimizationVerdict::AlreadyMinimal
        );
        let repro = report.repro.expect("already minimal repro emitted");
        assert_eq!(repro.retained_sources.len(), 1);
        assert!(repro.removed_source_ids.is_empty());
    }

    #[test]
    fn already_minimal_when_all_sources_are_required() {
        let package = two_source_package();
        let oracle = IncidentReplayOracle {
            kind: IncidentOracleKind::ProofCommandFailure,
            expected_signal: "remote proof command failed".to_string(),
            stable: true,
            required_source_roles: vec![
                IncidentReplaySourceRole::CrashPack,
                IncidentReplaySourceRole::TraceLog,
            ],
            required_trace_fingerprint: None,
        };
        let report = minimize_incident_replay_package(
            &package,
            oracle,
            IncidentReplayMinimizationConfig {
                step_budget: 8,
                shrink_feature_flags: false,
            },
        );

        assert_eq!(
            report.verdict,
            IncidentReplayMinimizationVerdict::AlreadyMinimal
        );
        assert!(report.steps.is_empty());
    }

    #[test]
    fn minimized_repro_json_round_trip_is_stable() {
        let package = two_source_package();
        let repro = package
            .minimize_repro(
                panic_oracle(),
                IncidentReplayMinimizationConfig {
                    step_budget: 8,
                    shrink_feature_flags: false,
                },
            )
            .repro
            .expect("repro emitted");
        let json = repro.to_json().expect("repro serializes");
        let parsed = IncidentMinimizedReplayRepro::from_json(&json).expect("repro parses");

        assert_eq!(repro.repro_id, parsed.repro_id);
        assert_eq!(repro, parsed);
    }

    fn minimized_crash_repro() -> IncidentMinimizedReplayRepro {
        two_source_package()
            .minimize_repro(
                panic_oracle(),
                IncidentReplayMinimizationConfig {
                    step_budget: 8,
                    shrink_feature_flags: false,
                },
            )
            .repro
            .expect("crash repro emitted")
    }

    #[test]
    fn promotion_class_selection_uses_oracle_and_sources() {
        let crash_report = promote_minimized_incident_repro(
            &minimized_crash_repro(),
            IncidentRegressionPromotionPolicy::default(),
        );
        assert_eq!(
            crash_report.verdict,
            IncidentRegressionPromotionVerdict::Promoted
        );
        assert_eq!(crash_report.target, IncidentRegressionProofTarget::UnitTest);

        let mut bundle = valid_bundle();
        bundle.sources[0].kind = IncidentSourceKind::ReadmeClaimFailure;
        bundle.sources[0].source_id = "readme-claim-main".to_string();
        let content_hash = bundle.sources[0].content_hash.clone();
        bundle.sources[0]
            .metadata
            .insert("observed_content_hash".to_string(), json!(content_hash));
        let package = bundle
            .import_replay_package()
            .package
            .expect("readme claim imports");
        let repro = package
            .minimize_repro(
                IncidentReplayOracle {
                    kind: IncidentOracleKind::ClaimDrift,
                    expected_signal: "region close claim drift".to_string(),
                    stable: true,
                    required_source_roles: vec![IncidentReplaySourceRole::ReadmeClaimFailure],
                    required_trace_fingerprint: None,
                },
                IncidentReplayMinimizationConfig {
                    step_budget: 8,
                    shrink_feature_flags: false,
                },
            )
            .repro
            .expect("claim drift repro emitted");
        let claim_report =
            promote_minimized_incident_repro(&repro, IncidentRegressionPromotionPolicy::default());

        assert_eq!(
            claim_report.target,
            IncidentRegressionProofTarget::GoldenArtifact
        );
        assert!(claim_report.has_proof());
    }

    #[test]
    fn unsupported_promotion_target_blocks() {
        let policy = IncidentRegressionPromotionPolicy {
            target: Some(IncidentRegressionProofTarget::ConformanceFixture),
            ..IncidentRegressionPromotionPolicy::default()
        };
        let report = promote_minimized_incident_repro(&minimized_crash_repro(), policy);

        assert_eq!(report.verdict, IncidentRegressionPromotionVerdict::Blocked);
        assert!(
            report.contains_block(IncidentRegressionPromotionBlockKind::UnsupportedPromotionTarget)
        );
        assert!(report.proof.is_none());
    }

    #[test]
    fn duplicate_seed_detection_blocks_repromotion() {
        let repro = minimized_crash_repro();
        let promoted =
            promote_minimized_incident_repro(&repro, IncidentRegressionPromotionPolicy::default());
        let seed_id = promoted
            .proof
            .as_ref()
            .expect("promotion proof emitted")
            .seed_id
            .clone();
        let report = promote_minimized_incident_repro(
            &repro,
            IncidentRegressionPromotionPolicy {
                existing_seed_ids: vec![seed_id],
                ..IncidentRegressionPromotionPolicy::default()
            },
        );

        assert_eq!(report.verdict, IncidentRegressionPromotionVerdict::Blocked);
        assert!(report.contains_block(IncidentRegressionPromotionBlockKind::DuplicateSeed));
    }

    #[test]
    fn stale_fixture_hash_rejects_promotion() {
        let repro = minimized_crash_repro();
        let report = promote_minimized_incident_repro(
            &repro,
            IncidentRegressionPromotionPolicy {
                expected_fixture_hashes: BTreeMap::from([(
                    "crashpack-main".to_string(),
                    "sha256:9999999999999999999999999999999999999999999999999999999999999999"
                        .to_string(),
                )]),
                ..IncidentRegressionPromotionPolicy::default()
            },
        );

        assert_eq!(report.verdict, IncidentRegressionPromotionVerdict::Blocked);
        assert!(report.contains_block(IncidentRegressionPromotionBlockKind::StaleFixtureHash));
    }

    #[test]
    fn redaction_policy_is_preserved_without_payload_leakage() {
        // Build a repro whose source carries a SENSITIVE payload snippet that is
        // distinct from the oracle's (non-sensitive) detection signal. The
        // promotion proof legitimately retains the oracle signal (it is the
        // replay detection criterion, not raw source material) but must NOT
        // reintroduce the redacted source payload snippet — it keeps only the
        // content hash of retained sources.
        const SENSITIVE_PAYLOAD: &str = "Authorization: Bearer leaked-secret-9f4c36b1";

        let mut bundle = valid_bundle();
        bundle.sources[0].payload_snippet = Some(SENSITIVE_PAYLOAD.to_string());
        bundle.sources[0].redaction_status = IncidentRedactionStatus::Redacted;

        let package = bundle
            .import_replay_package()
            .package
            .expect("fixture package imports");
        let repro = package
            .minimize_repro(
                IncidentReplayOracle {
                    kind: IncidentOracleKind::Panic,
                    // Non-sensitive crash descriptor, deliberately unrelated to the
                    // source payload above.
                    expected_signal: "panic-class:scheduler-seed-mismatch".to_string(),
                    stable: true,
                    required_source_roles: vec![IncidentReplaySourceRole::CrashPack],
                    required_trace_fingerprint: Some("0xfeedbeef".to_string()),
                },
                IncidentReplayMinimizationConfig {
                    step_budget: 8,
                    shrink_feature_flags: false,
                },
            )
            .repro
            .expect("crash repro emitted");

        let report = promote_minimized_incident_repro(
            &repro,
            IncidentRegressionPromotionPolicy {
                redaction_policy_id: "incident-redaction-v1".to_string(),
                ..IncidentRegressionPromotionPolicy::default()
            },
        );
        let proof = report.proof.expect("promotion proof emitted");
        let json = serde_json::to_string(&proof).expect("proof serializes");

        assert_eq!(proof.redaction_policy_id, "incident-redaction-v1");
        // The promoted proof is actionable: it carries at least one rch-executable
        // command for replaying the regression.
        assert!(
            proof
                .proof_commands
                .iter()
                .any(|command| command.executable_through_rch),
            "promotion proof must carry an rch-executable command"
        );
        assert!(
            !json.contains(SENSITIVE_PAYLOAD),
            "promotion proof must not reintroduce redacted source payload snippets"
        );
    }
