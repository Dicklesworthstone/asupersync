    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn minimal_json() -> &'static str {
        r#"{
            "id": "test-scenario",
            "description": "minimal test"
        }"#
    }

    #[test]
    fn parse_minimal_scenario() {
        let s: Scenario = serde_json::from_str(minimal_json()).unwrap();
        assert_eq!(s.id, "test-scenario");
        assert_eq!(s.schema_version, 1);
        assert_eq!(s.lab.seed, 42);
        assert_eq!(s.lab.worker_count, 1);
        assert!(s.faults.is_empty());
        assert!(s.participants.is_empty());
        assert_eq!(s.oracles, vec!["all"]);
        assert_eq!(s.resource_caps, ResourceCapsSection::default());
        assert_eq!(s.expected_invariants, default_expected_invariants());
        assert_eq!(s.minimization, MinimizationSection::default());
        assert_eq!(s.golden_projection, GoldenProjectionSection::default());
    }

    #[test]
    fn validate_minimal_scenario() {
        let s: Scenario = serde_json::from_str(minimal_json()).unwrap();
        let errors = s.validate();
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn validate_empty_id_rejected() {
        let json = r#"{"id": "", "description": "bad"}"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(errors.iter().any(|e| e.field == "id"));
    }

    #[test]
    fn validate_bad_schema_version() {
        let json = r#"{"schema_version": 99, "id": "x"}"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(errors.iter().any(|e| e.field == "schema_version"));
    }

    #[test]
    fn parse_chaos_preset_light() {
        let json = r#"{"id": "x", "chaos": {"preset": "light"}}"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        assert!(matches!(s.chaos, ChaosSection::Light));
    }

    #[test]
    fn parse_chaos_custom() {
        let json = r#"{
            "id": "x",
            "chaos": {
                "preset": "custom",
                "cancel_probability": 0.05,
                "delay_probability": 0.3,
                "io_error_probability": 0.1
            }
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        match s.chaos {
            ChaosSection::Custom {
                cancel_probability,
                delay_probability,
                io_error_probability,
                ..
            } => {
                assert!((cancel_probability - 0.05).abs() < f64::EPSILON);
                assert!((delay_probability - 0.3).abs() < f64::EPSILON);
                assert!((io_error_probability - 0.1).abs() < f64::EPSILON);
            }
            other => panic!("expected Custom, got {other:?}"), // ubs:ignore - test helper
        }
    }

    #[test]
    fn validate_chaos_bad_probability() {
        let json = r#"{
            "id": "x",
            "chaos": {"preset": "custom", "cancel_probability": 1.5}
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(errors.iter().any(|e| e.field == "chaos.cancel_probability"));
    }

    // br-asupersync-cb440b: NaN/Inf chaos probabilities must be rejected
    // with an explicit "must be a finite number" error rather than the
    // generic out-of-range message. This is the regression that proves
    // the chaos validator now matches the network validator's
    // is_finite-first pattern, instead of relying on the subtle fact
    // that NaN comparisons against a RangeInclusive happen to return
    // false.
    #[test]
    fn validate_chaos_rejects_nan_probability_with_finite_error() {
        // NaN cannot be expressed as a JSON literal, so we parse a
        // minimal scenario then mutate the chaos section directly.
        let mut s: Scenario = serde_json::from_str(r#"{"id":"x"}"#).unwrap();
        s.chaos = ChaosSection::Custom {
            cancel_probability: f64::NAN,
            delay_probability: 0.0,
            delay_min_ms: 0,
            delay_max_ms: 1,
            io_error_probability: 0.0,
            wakeup_storm_probability: 0.0,
            budget_exhaustion_probability: 0.0,
        };
        let errors = s.validate();
        let nan_error = errors
            .iter()
            .find(|e| e.field == "chaos.cancel_probability")
            .expect("chaos.cancel_probability NaN must be flagged");
        assert!(
            nan_error.message.contains("finite"),
            "NaN error message must say 'finite', got: {}",
            nan_error.message
        );
        assert!(
            nan_error.message.contains("NaN"),
            "NaN error message must include 'NaN', got: {}",
            nan_error.message
        );
    }

    #[test]
    fn validate_chaos_rejects_infinity_probability_with_finite_error() {
        let mut s: Scenario = serde_json::from_str(r#"{"id":"x"}"#).unwrap();
        s.chaos = ChaosSection::Custom {
            cancel_probability: 0.0,
            delay_probability: 0.0,
            delay_min_ms: 0,
            delay_max_ms: 1,
            io_error_probability: 0.0,
            wakeup_storm_probability: f64::INFINITY,
            budget_exhaustion_probability: f64::NEG_INFINITY,
        };
        let errors = s.validate();
        let inf_storm = errors
            .iter()
            .find(|e| e.field == "chaos.wakeup_storm_probability")
            .expect("chaos.wakeup_storm_probability +Inf must be flagged");
        assert!(
            inf_storm.message.contains("finite"),
            "+Inf error must say 'finite', got: {}",
            inf_storm.message
        );
        let neg_inf_budget = errors
            .iter()
            .find(|e| e.field == "chaos.budget_exhaustion_probability")
            .expect("chaos.budget_exhaustion_probability -Inf must be flagged");
        assert!(
            neg_inf_budget.message.contains("finite"),
            "-Inf error must say 'finite', got: {}",
            neg_inf_budget.message
        );
    }

    #[test]
    fn parse_network_preset_wan() {
        let json = r#"{"id": "x", "network": {"preset": "wan"}}"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        assert_eq!(s.network.preset, NetworkPreset::Wan);
    }

    #[test]
    fn parse_network_link_override() {
        let json = r#"{
            "id": "x",
            "network": {
                "preset": "lan",
                "links": {
                    "alice->bob": { "packet_loss": 0.5 }
                }
            }
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let link = s.network.links.get("alice->bob").unwrap();
        assert!((link.packet_loss.unwrap() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn validate_bad_link_key() {
        let json = r#"{
            "id": "x",
            "network": {"links": {"alice_bob": {}}}
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(errors.iter().any(|e| e.field.contains("network.links")));
    }

    #[test]
    fn validate_link_probability_out_of_range() {
        let json = r#"{
            "id": "x",
            "network": {
                "links": {
                    "alice->bob": { "packet_loss": 1.5 }
                }
            }
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "network.links.alice->bob.packet_loss")
        );
    }

    #[test]
    fn validate_uniform_latency_min_max_order() {
        let json = r#"{
            "id": "x",
            "network": {
                "links": {
                    "alice->bob": {
                        "latency": { "model": "uniform", "min_ms": 20, "max_ms": 10 }
                    }
                }
            }
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "network.links.alice->bob.latency")
        );
    }

    #[test]
    fn parse_fault_events() {
        let json = r#"{
            "id": "x",
            "faults": [
                {"at_ms": 100, "action": "partition", "args": {"from": "a", "to": "b"}},
                {"at_ms": 500, "action": "heal", "args": {"from": "a", "to": "b"}}
            ]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        assert_eq!(s.faults.len(), 2);
        assert_eq!(s.faults[0].at_ms, 100);
        assert!(matches!(s.faults[0].action, FaultAction::Partition));
        assert_eq!(s.faults[1].at_ms, 500);
        assert!(matches!(s.faults[1].action, FaultAction::Heal));
    }

    #[test]
    fn validate_unordered_faults() {
        let json = r#"{
            "id": "x",
            "faults": [
                {"at_ms": 500, "action": "partition"},
                {"at_ms": 100, "action": "heal"}
            ]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(errors.iter().any(|e| e.field == "faults"));
    }

    #[test]
    fn validate_fault_action_args_fail_closed() {
        let json = r#"{
            "id": "x",
            "faults": [
                {"at_ms": 1, "action": "partition"},
                {"at_ms": 2, "action": "host_crash", "args": {"host": ""}},
                {"at_ms": 3, "action": "clock_skew", "args": {"host": "alice", "skew_ms": "fast"}},
                {"at_ms": 4, "action": "disk_pressure", "args": {"path": "", "bytes": 0}},
                {"at_ms": 5, "action": "delayed_cleanup", "args": {"phase": "", "delay_ms": 0}},
                {"at_ms": 6, "action": "process_stall", "args": {"host": "", "duration_ms": 0}}
            ]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();

        assert!(errors.iter().any(|e| e.field == "faults[0].args.from"));
        assert!(errors.iter().any(|e| e.field == "faults[0].args.to"));
        assert!(errors.iter().any(|e| e.field == "faults[1].args.host"));
        assert!(errors.iter().any(|e| e.field == "faults[2].args.skew_ms"));
        assert!(errors.iter().any(|e| e.field == "faults[3].args.path"));
        assert!(errors.iter().any(|e| e.field == "faults[3].args.bytes"));
        assert!(errors.iter().any(|e| e.field == "faults[4].args.phase"));
        assert!(errors.iter().any(|e| e.field == "faults[4].args.delay_ms"));
        assert!(errors.iter().any(|e| e.field == "faults[5].args.host"));
        assert!(
            errors
                .iter()
                .any(|e| e.field == "faults[5].args.duration_ms")
        );
    }

    #[test]
    fn validate_fault_args_reference_declared_participants() {
        let json = r#"{
            "id": "x",
            "participants": [
                {"name": "alice"},
                {"name": "bob"}
            ],
            "faults": [
                {"at_ms": 1, "action": "partition", "args": {"from": "alice", "to": "mallory"}},
                {"at_ms": 2, "action": "heal", "args": {"from": "bob", "to": "bob"}},
                {"at_ms": 3, "action": "clock_reset", "args": {"host": "mallory"}},
                {"at_ms": 4, "action": "process_stall", "args": {"host": "mallory", "duration_ms": 10}}
            ]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();

        assert!(errors.iter().any(|e| {
            e.field == "faults[0].args.to" && e.message.contains("unknown participant")
        }));
        assert!(
            errors
                .iter()
                .any(|e| { e.field == "faults[1].args.to" && e.message.contains("distinct") })
        );
        assert!(errors.iter().any(|e| {
            e.field == "faults[2].args.host" && e.message.contains("unknown participant")
        }));
        assert!(errors.iter().any(|e| {
            e.field == "faults[3].args.host" && e.message.contains("unknown participant")
        }));
    }

    #[test]
    fn parse_disk_process_and_cleanup_fault_events() {
        let json = r#"{
            "id": "x",
            "participants": [{"name": "worker-a"}],
            "faults": [
                {"at_ms": 10, "action": "disk_pressure", "args": {"path": "target/proof", "bytes": 4096}},
                {"at_ms": 20, "action": "delayed_cleanup", "args": {"phase": "finalizers", "delay_ms": 25}},
                {"at_ms": 30, "action": "process_stall", "args": {"host": "worker-a", "duration_ms": 40}},
                {"at_ms": 80, "action": "process_resume", "args": {"host": "worker-a"}},
                {"at_ms": 90, "action": "disk_recovered", "args": {"path": "target/proof"}}
            ]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        assert_eq!(s.faults.len(), 5);
        assert!(matches!(s.faults[0].action, FaultAction::DiskPressure));
        assert!(matches!(s.faults[1].action, FaultAction::DelayedCleanup));
        assert!(matches!(s.faults[2].action, FaultAction::ProcessStall));
        assert!(matches!(s.faults[3].action, FaultAction::ProcessResume));
        assert!(matches!(s.faults[4].action, FaultAction::DiskRecovered));
        assert!(
            s.validate().is_empty(),
            "new DSL fault actions must validate"
        );
    }

    #[test]
    fn parse_participants() {
        let json = r#"{
            "id": "x",
            "participants": [
                {"name": "alice", "role": "sender"},
                {"name": "bob", "role": "receiver"}
            ]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        assert_eq!(s.participants.len(), 2);
        assert_eq!(s.participants[0].name, "alice");
        assert_eq!(s.participants[1].role, "receiver");
    }

    #[test]
    fn validate_duplicate_participant() {
        let json = r#"{
            "id": "x",
            "participants": [
                {"name": "alice"},
                {"name": "alice"}
            ]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(errors.iter().any(|e| e.message.contains("duplicate")));
    }

    #[test]
    fn parse_cancellation_strategy() {
        let json = r#"{
            "id": "x",
            "cancellation": {
                "strategy": "random_sample",
                "count": 100
            }
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let cancel = s.cancellation.as_ref().unwrap();
        assert!(matches!(
            cancel.strategy,
            CancellationStrategy::RandomSample
        ));
        assert_eq!(cancel.count, Some(100));
    }

    #[test]
    fn validate_missing_count() {
        let json = r#"{
            "id": "x",
            "cancellation": {"strategy": "random_sample"}
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(errors.iter().any(|e| e.field == "cancellation.count"));
    }

    #[test]
    fn parse_source_backed_dsl_fields() {
        let json = r#"{
            "id": "chaos-partition-cancel-storm",
            "description": "partition plus cancellation storm",
            "lab": {"seed": 340334, "worker_count": 2, "max_steps": 1000},
            "participants": [
                {"name": "alice", "role": "sender"},
                {"name": "bob", "role": "receiver"}
            ],
            "faults": [
                {"at_ms": 100, "action": "partition", "args": {"from": "alice", "to": "bob"}},
                {"at_ms": 500, "action": "heal", "args": {"from": "alice", "to": "bob"}}
            ],
            "cancellation": {"strategy": "random_sample", "count": 8},
            "resource_caps": {
                "max_artifact_bytes": 65536,
                "max_fault_events": 8,
                "max_counterexample_events": 16
            },
            "expected_invariants": [
                "quiescence",
                "losers_drained",
                "no_obligation_leaks",
                "deterministic_replay"
            ],
            "minimization": {
                "enabled": true,
                "max_evaluations": 64,
                "max_counterexample_events": 16
            },
            "golden_projection": {
                "format": "json",
                "canonicalized": true,
                "redacted": true
            }
        }"#;

        let s: Scenario = serde_json::from_str(json).unwrap();
        assert_eq!(s.lab.seed, 340_334);
        assert_eq!(s.resource_caps.max_artifact_bytes, Some(65_536));
        assert_eq!(s.resource_caps.max_fault_events, Some(8));
        assert_eq!(s.resource_caps.max_counterexample_events, Some(16));
        assert_eq!(
            s.expected_invariants,
            vec![
                "quiescence".to_string(),
                "losers_drained".to_string(),
                "no_obligation_leaks".to_string(),
                "deterministic_replay".to_string()
            ]
        );
        assert!(s.minimization.enabled);
        assert_eq!(s.minimization.max_evaluations, Some(64));
        assert_eq!(s.minimization.max_counterexample_events, Some(16));
        assert_eq!(s.golden_projection.format, GoldenProjectionFormat::Json);
        assert!(s.golden_projection.canonicalized);
        assert!(s.golden_projection.redacted);
        assert!(
            s.validate().is_empty(),
            "source-backed scenario must validate"
        );
    }

    #[test]
    fn validate_resource_caps_bound_fault_count() {
        let json = r#"{
            "id": "x",
            "participants": [{"name": "alice"}, {"name": "bob"}],
            "faults": [
                {"at_ms": 1, "action": "partition", "args": {"from": "alice", "to": "bob"}},
                {"at_ms": 2, "action": "heal", "args": {"from": "alice", "to": "bob"}}
            ],
            "resource_caps": {
                "max_artifact_bytes": 0,
                "max_fault_events": 1,
                "max_counterexample_events": 0
            }
        }"#;

        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "resource_caps.max_artifact_bytes")
        );
        assert!(
            errors
                .iter()
                .any(|e| e.field == "resource_caps.max_fault_events")
        );
        assert!(
            errors
                .iter()
                .any(|e| e.field == "resource_caps.max_counterexample_events")
        );
    }

    #[test]
    fn validate_expected_invariants_fail_closed() {
        let json = r#"{
            "id": "x",
            "expected_invariants": ["quiescence", "", "quiescence", "mystery"]
        }"#;

        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(errors.iter().any(|e| {
            e.field == "expected_invariants[1]" && e.message.contains("must not be empty")
        }));
        assert!(
            errors.iter().any(|e| {
                e.field == "expected_invariants[2]" && e.message.contains("duplicate")
            })
        );
        assert!(
            errors.iter().any(|e| {
                e.field == "expected_invariants[3]" && e.message.contains("unsupported")
            })
        );
    }

    #[test]
    fn validate_minimization_requires_positive_budget_when_enabled() {
        let json = r#"{
            "id": "x",
            "minimization": {
                "enabled": true,
                "max_counterexample_events": 0
            }
        }"#;

        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "minimization.max_evaluations")
        );
        assert!(
            errors
                .iter()
                .any(|e| e.field == "minimization.max_counterexample_events")
        );
    }

    #[test]
    fn validate_golden_projection_requires_canonical_redacted_output() {
        let json = r#"{
            "id": "x",
            "golden_projection": {
                "format": "markdown",
                "canonicalized": false,
                "redacted": false
            }
        }"#;

        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "golden_projection.canonicalized")
        );
        assert!(
            errors
                .iter()
                .any(|e| e.field == "golden_projection.redacted")
        );
    }

    #[test]
    fn validate_includes_path_traversal_security() {
        // Test empty path rejection
        let json = r#"{
            "id": "test",
            "include": [{"path": ""}]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "include[0].path" && e.message.contains("empty"))
        );

        // Test absolute path rejection (Unix style)
        let json = r#"{
            "id": "test",
            "include": [{"path": "/etc/passwd"}]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "include[0].path" && e.message.contains("absolute"))
        );

        // Test absolute path rejection (Windows style)
        let json = r#"{
            "id": "test",
            "include": [{"path": "\\windows\\system32\\config\\sam"}]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "include[0].path" && e.message.contains("absolute"))
        );

        // Test path traversal rejection
        let json = r#"{
            "id": "test",
            "include": [{"path": "../../../etc/passwd.yaml"}]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "include[0].path" && e.message.contains("path traversal"))
        );

        // Test subtler path traversal
        let json = r#"{
            "id": "test",
            "include": [{"path": "configs/../secrets.yaml"}]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "include[0].path" && e.message.contains("path traversal"))
        );

        // Test control character rejection (null byte)
        let json = r#"{
            "id": "test",
            "include": [{"path": "config\u0000.yaml"}]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "include[0].path" && e.message.contains("control characters"))
        );

        // Test invalid character rejection
        let json = r#"{
            "id": "test",
            "include": [{"path": "config$evil.yaml"}]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "include[0].path" && e.message.contains("invalid characters"))
        );

        // Test path length limit
        let long_path = "a".repeat(256) + ".yaml";
        let json = format!(
            r#"{{"id": "test", "include": [{{"path": "{}"}}]}}"#,
            long_path
        );
        let s: Scenario = serde_json::from_str(&json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "include[0].path" && e.message.contains("too long"))
        );

        // Test extension requirement (missing extension)
        let json = r#"{
            "id": "test",
            "include": [{"path": "config.txt"}]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors.iter().any(|e| e.field == "include[0].path"
                && e.message.contains("must end with .yaml or .yml"))
        );

        // Test valid path passes all checks
        let json = r#"{
            "id": "test",
            "include": [{"path": "config/base.yaml"}]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let errors = s.validate();
        assert!(
            errors
                .iter()
                .all(|e| !e.field.starts_with("include[0].path"))
        );
    }

    #[test]
    fn to_lab_config_defaults() {
        let s: Scenario = serde_json::from_str(minimal_json()).unwrap();
        let config = s.to_lab_config();
        assert_eq!(config.seed, 42);
        assert_eq!(config.worker_count, 1);
        assert_eq!(config.trace_capacity, 4096);
        assert!(config.panic_on_obligation_leak);
    }

    #[test]
    fn to_lab_config_chaos_light() {
        let json = r#"{"id": "x", "chaos": {"preset": "light"}}"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let config = s.to_lab_config();
        assert!(config.has_chaos());
    }

    #[test]
    fn to_lab_config_custom_seed() {
        let json = r#"{"id": "x", "lab": {"seed": 12345, "worker_count": 4}}"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        let config = s.to_lab_config();
        assert_eq!(config.seed, 12345);
        assert_eq!(config.worker_count, 4);
    }

    #[test]
    fn canonical_contract_full_json_roundtrip() {
        let json = r#"{
            "id": "roundtrip-test",
            "description": "full roundtrip",
            "lab": {"seed": 99, "worker_count": 2},
            "chaos": {"preset": "heavy"},
            "network": {"preset": "wan"},
            "participants": [
                {"name": "alice", "role": "sender"},
                {"name": "bob", "role": "receiver"}
            ],
            "faults": [{
                "at_ms": 100,
                "action": "partition",
                "args": {"from": "alice", "to": "bob"}
            }],
            "resource_caps": {"max_artifact_bytes": 1024, "max_fault_events": 2},
            "expected_invariants": ["quiescence", "deterministic_replay"],
            "minimization": {"enabled": false, "max_counterexample_events": 8},
            "golden_projection": {"format": "markdown", "canonicalized": true, "redacted": true}
        }"#;
        let s1: Scenario = serde_json::from_str(json).unwrap();
        assert!(s1.validate().is_empty());
        let serialized = s1.to_json().unwrap();
        let s2: Scenario = Scenario::from_json(&serialized).unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn canonical_contract_matches_byte_golden() {
        let scenario = Scenario::from_json(minimal_json()).unwrap();
        let canonical = scenario.to_json().unwrap();

        assert_eq!(
            canonical,
            r#"{"cancellation":null,"chaos":{"preset":"off"},"description":"minimal test","expected_invariants":["quiescence","losers_drained","no_obligation_leaks","deterministic_replay"],"faults":[],"golden_projection":{"canonicalized":true,"format":"json","redacted":true},"id":"test-scenario","include":[],"lab":{"entropy_seed":null,"futurelock_max_idle_steps":10000,"max_steps":100000,"panic_on_futurelock":true,"panic_on_obligation_leak":true,"replay_recording":false,"seed":42,"trace_capacity":4096,"worker_count":1},"metadata":{},"minimization":{"enabled":false,"max_counterexample_events":null,"max_evaluations":null},"network":{"links":{},"preset":"ideal"},"oracles":["all"],"participants":[],"resource_caps":{"max_artifact_bytes":null,"max_counterexample_events":null,"max_fault_events":null},"schema_version":1}"#
        );
    }

    #[test]
    fn canonical_contract_orders_dynamic_objects_recursively() {
        let value = serde_json::json!({
            "z": {"beta": 2, "alpha": 1},
            "a": [{"delta": 4, "charlie": 3}],
        });
        let canonical = canonicalize_json_value(value);

        assert_eq!(
            serde_json::to_string(&canonical).unwrap(),
            r#"{"a":[{"charlie":3,"delta":4}],"z":{"alpha":1,"beta":2}}"#
        );
    }

    #[test]
    fn canonical_contract_migrates_missing_version_without_meaning_change() {
        let implicit = Scenario::from_json(r#"{"id":"legacy-defaulted-version"}"#).unwrap();
        let explicit =
            Scenario::from_json(r#"{"schema_version":1,"id":"legacy-defaulted-version"}"#).unwrap();

        assert_eq!(implicit, explicit);
        assert_eq!(implicit.to_json().unwrap(), explicit.to_json().unwrap());
        assert!(implicit.validate().is_empty());
    }

    #[test]
    fn parse_metadata() {
        let json = r#"{
            "id": "x",
            "metadata": {"git_sha": "abc123", "author": "bot"}
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        assert_eq!(s.metadata.get("git_sha").unwrap(), "abc123");
    }

    #[test]
    fn parse_latency_models() {
        let json = r#"{
            "id": "x",
            "network": {
                "preset": "ideal",
                "links": {
                    "a->b": {"latency": {"model": "fixed", "ms": 5}},
                    "b->c": {"latency": {"model": "uniform", "min_ms": 1, "max_ms": 10}},
                    "c->d": {"latency": {"model": "normal", "mean_ms": 50, "stddev_ms": 10}}
                }
            }
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        assert_eq!(s.network.links.len(), 3);
        let ab = s.network.links.get("a->b").unwrap();
        assert!(matches!(ab.latency, Some(LatencySpec::Fixed { ms: 5 })));
    }

    #[test]
    fn parse_include() {
        let json = r#"{
            "id": "x",
            "include": [{"path": "base.yaml"}]
        }"#;
        let s: Scenario = serde_json::from_str(json).unwrap();
        assert_eq!(s.include.len(), 1);
        assert_eq!(s.include[0].path, "base.yaml");
    }

    #[test]
    fn network_preset_debug_clone_copy_eq() {
        let p = NetworkPreset::Wan;
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Wan"));

        let p2 = p;
        assert_eq!(p, p2);

        let p3 = p;
        assert_eq!(p, p3);

        assert_ne!(NetworkPreset::Ideal, NetworkPreset::Lossy);
    }

    #[test]
    fn chaos_section_debug_clone_default() {
        let c = ChaosSection::default();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Off"));

        let c2 = c;
        let dbg2 = format!("{c2:?}");
        assert_eq!(dbg, dbg2);
    }

    #[test]
    fn fault_action_debug_clone() {
        let a = FaultAction::Partition;
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Partition"));

        let a2 = a;
        let dbg2 = format!("{a2:?}");
        assert_eq!(dbg, dbg2);
    }

    #[test]
    fn validation_error_debug_clone() {
        let e = ValidationError {
            field: "lab.seed".into(),
            message: "must be positive".into(),
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("lab.seed"));

        let e2 = e;
        assert_eq!(e2.field, "lab.seed");
        assert_eq!(e2.message, "must be positive");
    }
