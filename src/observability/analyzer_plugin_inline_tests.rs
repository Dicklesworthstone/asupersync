    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[derive(Debug, Clone)]
    enum TestMode {
        Success(Vec<AnalyzerFinding>),
        Error(AnalyzerPluginRunError),
        Panic,
    }

    struct TestPlugin {
        descriptor: AnalyzerPluginDescriptor,
        mode: TestMode,
    }

    impl AnalyzerPlugin for TestPlugin {
        fn descriptor(&self) -> AnalyzerPluginDescriptor {
            self.descriptor.clone()
        }

        fn analyze(
            &self,
            _request: &AnalyzerRequest,
            negotiated_input_schema: AnalyzerSchemaVersion,
        ) -> Result<AnalyzerOutput, AnalyzerPluginRunError> {
            match &self.mode {
                TestMode::Success(findings) => Ok(AnalyzerOutput {
                    schema_version: self.descriptor.output_schema,
                    findings: findings.clone(),
                    summary: format!("schema {negotiated_input_schema:?}"),
                }),
                TestMode::Error(err) => Err(err.clone()),
                TestMode::Panic => panic!("plugin panic for test"), // ubs:ignore - test logic
            }
        }
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn descriptor(
        plugin_id: &str,
        supported_input_schemas: Vec<AnalyzerSchemaVersion>,
        required_capabilities: Vec<AnalyzerCapability>,
    ) -> AnalyzerPluginDescriptor {
        AnalyzerPluginDescriptor {
            plugin_id: plugin_id.to_string(),
            display_name: format!("{plugin_id} display"),
            plugin_version: "1.0.0".to_string(),
            supported_input_schemas,
            output_schema: AnalyzerSchemaVersion::new(1, 0),
            required_capabilities,
            sandbox_policy: AnalyzerSandboxPolicy::DeterministicReadOnly,
        }
    }

    fn request_with_caps(granted_capabilities: Vec<AnalyzerCapability>) -> AnalyzerRequest {
        AnalyzerRequest::new(
            "run-analyzer-pack".to_string(),
            "corr-001".to_string(),
            ".".to_string(),
            AnalyzerSchemaVersion::new(1, 2),
            granted_capabilities,
        )
    }

    #[test]
    fn register_rejects_duplicate_plugin_id() {
        init_test("register_rejects_duplicate_plugin_id");
        let mut registry = AnalyzerPluginRegistry::new();
        let plugin_a = Arc::new(TestPlugin {
            descriptor: descriptor(
                "alpha-plugin",
                vec![AnalyzerSchemaVersion::new(1, 0)],
                vec![AnalyzerCapability::WorkspaceRead],
            ),
            mode: TestMode::Success(Vec::new()),
        });
        let plugin_b = Arc::new(TestPlugin {
            descriptor: descriptor(
                "alpha-plugin",
                vec![AnalyzerSchemaVersion::new(1, 0)],
                vec![AnalyzerCapability::WorkspaceRead],
            ),
            mode: TestMode::Success(Vec::new()),
        });
        registry
            .register(plugin_a)
            .expect("first registration succeeds");
        let err = registry
            .register(plugin_b)
            .expect_err("duplicate registration must fail");
        assert!(matches!(
            err,
            PluginRegistrationError::DuplicatePluginId { .. }
        ));
        crate::test_complete!("register_rejects_duplicate_plugin_id");
    }

    #[test]
    fn schema_negotiation_prefers_exact_then_fallback() {
        init_test("schema_negotiation_prefers_exact_then_fallback");
        let supported = vec![
            AnalyzerSchemaVersion::new(1, 0),
            AnalyzerSchemaVersion::new(1, 1),
            AnalyzerSchemaVersion::new(1, 3),
        ];

        let exact = negotiate_schema_version(AnalyzerSchemaVersion::new(1, 1), &supported);
        assert_eq!(exact.decision, SchemaDecision::Exact);
        assert_eq!(
            exact.selected_schema,
            Some(AnalyzerSchemaVersion::new(1, 1))
        );

        let fallback = negotiate_schema_version(AnalyzerSchemaVersion::new(1, 2), &supported);
        assert_eq!(
            fallback.decision,
            SchemaDecision::BackwardCompatibleFallback
        );
        assert_eq!(
            fallback.selected_schema,
            Some(AnalyzerSchemaVersion::new(1, 1))
        );

        let incompatible = negotiate_schema_version(AnalyzerSchemaVersion::new(2, 0), &supported);
        assert_eq!(incompatible.decision, SchemaDecision::IncompatibleMajor);
        assert!(incompatible.selected_schema.is_none());
        crate::test_complete!("schema_negotiation_prefers_exact_then_fallback");
    }

    #[test]
    fn run_pack_is_deterministic_and_aggregates_findings() {
        init_test("run_pack_is_deterministic_and_aggregates_findings");
        let mut registry = AnalyzerPluginRegistry::new();

        registry
            .register(Arc::new(TestPlugin {
                descriptor: descriptor(
                    "zeta-plugin",
                    vec![
                        AnalyzerSchemaVersion::new(1, 0),
                        AnalyzerSchemaVersion::new(1, 2),
                    ],
                    vec![AnalyzerCapability::WorkspaceRead],
                ),
                mode: TestMode::Success(vec![AnalyzerFinding {
                    finding_id: "zeta-002".to_string(),
                    severity: AnalyzerSeverity::Warn,
                    summary: "zeta warning".to_string(),
                    confidence_bps: 8300,
                }]),
            }))
            .expect("register zeta");
        registry
            .register(Arc::new(TestPlugin {
                descriptor: descriptor(
                    "alpha-plugin",
                    vec![
                        AnalyzerSchemaVersion::new(1, 0),
                        AnalyzerSchemaVersion::new(1, 2),
                    ],
                    vec![AnalyzerCapability::WorkspaceRead],
                ),
                mode: TestMode::Success(vec![AnalyzerFinding {
                    finding_id: "alpha-001".to_string(),
                    severity: AnalyzerSeverity::Error,
                    summary: "alpha error".to_string(),
                    confidence_bps: 9200,
                }]),
            }))
            .expect("register alpha");

        let report = run_analyzer_plugin_pack_smoke(
            &registry,
            &request_with_caps(vec![AnalyzerCapability::WorkspaceRead]),
        );
        assert_eq!(
            report.execution_order,
            vec!["alpha-plugin".to_string(), "zeta-plugin".to_string()]
        );
        assert_eq!(report.executions.len(), 2);
        assert_eq!(
            report
                .executions
                .iter()
                .map(|record| record.state)
                .collect::<Vec<_>>(),
            vec![
                PluginExecutionState::Succeeded,
                PluginExecutionState::Succeeded
            ]
        );
        assert_eq!(report.aggregated_findings.len(), 2);
        assert_eq!(report.aggregated_findings[0].plugin_id, "alpha-plugin");
        assert_eq!(report.aggregated_findings[1].plugin_id, "zeta-plugin");
        crate::test_complete!("run_pack_is_deterministic_and_aggregates_findings");
    }

    #[test]
    fn run_pack_isolates_error_and_panic_plugins() {
        init_test("run_pack_isolates_error_and_panic_plugins");
        let mut registry = AnalyzerPluginRegistry::new();

        registry
            .register(Arc::new(TestPlugin {
                descriptor: descriptor(
                    "ok-plugin",
                    vec![AnalyzerSchemaVersion::new(1, 0)],
                    vec![AnalyzerCapability::WorkspaceRead],
                ),
                mode: TestMode::Success(vec![AnalyzerFinding {
                    finding_id: "ok-001".to_string(),
                    severity: AnalyzerSeverity::Info,
                    summary: "ok".to_string(),
                    confidence_bps: 7000,
                }]),
            }))
            .expect("register ok");
        registry
            .register(Arc::new(TestPlugin {
                descriptor: descriptor(
                    "error-plugin",
                    vec![AnalyzerSchemaVersion::new(1, 0)],
                    vec![AnalyzerCapability::WorkspaceRead],
                ),
                mode: TestMode::Error(AnalyzerPluginRunError::new(
                    "plugin_failed",
                    "typed failure",
                )),
            }))
            .expect("register error");
        registry
            .register(Arc::new(TestPlugin {
                descriptor: descriptor(
                    "panic-plugin",
                    vec![AnalyzerSchemaVersion::new(1, 0)],
                    vec![AnalyzerCapability::WorkspaceRead],
                ),
                mode: TestMode::Panic,
            }))
            .expect("register panic");

        let report = run_analyzer_plugin_pack_smoke(
            &registry,
            &request_with_caps(vec![AnalyzerCapability::WorkspaceRead]),
        );
        assert_eq!(report.executions.len(), 3);
        let states: BTreeMap<&str, PluginExecutionState> = report
            .executions
            .iter()
            .map(|record| (record.plugin_id.as_str(), record.state))
            .collect();
        assert_eq!(
            states.get("ok-plugin"),
            Some(&PluginExecutionState::Succeeded)
        );
        assert_eq!(
            states.get("error-plugin"),
            Some(&PluginExecutionState::Failed)
        );
        assert_eq!(
            states.get("panic-plugin"),
            Some(&PluginExecutionState::Panicked)
        );
        assert_eq!(report.aggregated_findings.len(), 1);
        assert_eq!(report.aggregated_findings[0].plugin_id, "ok-plugin");
        assert!(
            report
                .lifecycle_events
                .iter()
                .any(|event| event.phase == PluginLifecyclePhase::Panicked),
            "panic should be surfaced via lifecycle events"
        );
        crate::test_complete!("run_pack_isolates_error_and_panic_plugins");
    }

    #[test]
    fn run_pack_skips_missing_capabilities_and_incompatible_schema() {
        init_test("run_pack_skips_missing_capabilities_and_incompatible_schema");
        let mut registry = AnalyzerPluginRegistry::new();

        registry
            .register(Arc::new(TestPlugin {
                descriptor: descriptor(
                    "cap-plugin",
                    vec![AnalyzerSchemaVersion::new(1, 0)],
                    vec![AnalyzerCapability::EvidenceRead],
                ),
                mode: TestMode::Success(Vec::new()),
            }))
            .expect("register cap-plugin");

        registry
            .register(Arc::new(TestPlugin {
                descriptor: descriptor(
                    "schema-plugin",
                    vec![AnalyzerSchemaVersion::new(2, 0)],
                    vec![AnalyzerCapability::WorkspaceRead],
                ),
                mode: TestMode::Success(Vec::new()),
            }))
            .expect("register schema-plugin");

        let report = run_analyzer_plugin_pack_smoke(
            &registry,
            &request_with_caps(vec![AnalyzerCapability::WorkspaceRead]),
        );
        let states: BTreeMap<&str, PluginExecutionState> = report
            .executions
            .iter()
            .map(|record| (record.plugin_id.as_str(), record.state))
            .collect();
        assert_eq!(
            states.get("cap-plugin"),
            Some(&PluginExecutionState::SkippedMissingCapabilities)
        );
        assert_eq!(
            states.get("schema-plugin"),
            Some(&PluginExecutionState::SkippedIncompatibleSchema)
        );
        assert!(report.aggregated_findings.is_empty());
        crate::test_complete!("run_pack_skips_missing_capabilities_and_incompatible_schema");
    }

    #[test]
    fn run_pack_rejects_duplicate_finding_ids_as_contract_violation() {
        init_test("run_pack_rejects_duplicate_finding_ids_as_contract_violation");
        let mut registry = AnalyzerPluginRegistry::new();

        registry
            .register(Arc::new(TestPlugin {
                descriptor: descriptor(
                    "dup-plugin",
                    vec![AnalyzerSchemaVersion::new(1, 0)],
                    vec![AnalyzerCapability::WorkspaceRead],
                ),
                mode: TestMode::Success(vec![
                    AnalyzerFinding {
                        finding_id: "dup-001".to_string(),
                        severity: AnalyzerSeverity::Warn,
                        summary: "first duplicate".to_string(),
                        confidence_bps: 6100,
                    },
                    AnalyzerFinding {
                        finding_id: "dup-001".to_string(),
                        severity: AnalyzerSeverity::Error,
                        summary: "second duplicate".to_string(),
                        confidence_bps: 9200,
                    },
                ]),
            }))
            .expect("register dup-plugin");

        let report = run_analyzer_plugin_pack_smoke(
            &registry,
            &request_with_caps(vec![AnalyzerCapability::WorkspaceRead]),
        );
        assert_eq!(report.executions.len(), 1);
        assert_eq!(report.executions[0].plugin_id, "dup-plugin");
        assert_eq!(report.executions[0].state, PluginExecutionState::Failed);
        assert_eq!(
            report.executions[0].error_code.as_deref(),
            Some("duplicate_finding_id")
        );
        assert!(report.aggregated_findings.is_empty());
        assert!(
            report.lifecycle_events.iter().any(|event| {
                event.plugin_id == "dup-plugin"
                    && event.phase == PluginLifecyclePhase::ContractViolation
                    && event.message.contains("duplicate finding_id")
            }),
            "duplicate finding ids should surface as a contract violation"
        );
        crate::test_complete!("run_pack_rejects_duplicate_finding_ids_as_contract_violation");
    }
