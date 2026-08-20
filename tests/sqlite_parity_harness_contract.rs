//! Contract for the cycle-safe neutral SQLite parity harness.

use std::collections::BTreeSet;

use serde_json::Value;
use sha2::{Digest, Sha256};

const ROOT_MANIFEST: &str = include_str!("../Cargo.toml");
const ROOT_LOCK: &str = include_str!("../Cargo.lock");
const CONSUMER_MANIFEST: &str = include_str!("fixtures/sqlite-parity-consumer/Cargo.toml");
const CONSUMER_LOCK: &str = include_str!("fixtures/sqlite-parity-consumer/Cargo.lock");
const VECTORS: &str = include_str!("../artifacts/sqlite_conformance_vectors_v1.json");
const HARNESS: &str = include_str!("../artifacts/sqlite_parity_harness_v1.json");
const DOC: &str = include_str!("../docs/sqlite_parity_harness.md");
const SQLITE_SOURCE: &str = include_str!("../src/database/sqlite.rs");
const CONSUMER_SOURCE: &str = include_str!("fixtures/sqlite-parity-consumer/src/main.rs");
const PREPARED_CONFORMANCE_SOURCE: &str = include_str!("conformance/sqlite_prepared_statements.rs");
const REAL_DISK_CANCEL_ROLLBACK_SOURCE: &str = include_str!("sqlite_real_disk_cancel_rollback.rs");

fn parse_json(source: &str) -> Value {
    serde_json::from_str(source).expect("contract JSON must parse")
}

fn sha256(source: &str) -> String {
    hex::encode(Sha256::digest(source.as_bytes()))
}

#[test]
fn dependency_direction_is_cycle_safe_and_runtime_boundaries_are_explicit() {
    let root_manifest = ROOT_MANIFEST.to_ascii_lowercase();
    assert!(!root_manifest.contains("fsqlite"));
    assert!(!root_manifest.contains("frankensqlite"));
    assert!(!ROOT_LOCK.contains("name = \"fsqlite\""));

    assert!(CONSUMER_MANIFEST.contains("[workspace]"));
    assert!(CONSUMER_MANIFEST.contains("asupersync = { path = \"../../..\""));
    assert!(
        CONSUMER_MANIFEST
            .contains("git = \"https://github.com/Dicklesworthstone/frankensqlite.git\"")
    );
    assert!(CONSUMER_MANIFEST.contains("rev = \"92f9e9833f859ebcbe27e9fef16d9cad4372bbd7\""));
    assert!(CONSUMER_MANIFEST.contains("features = [\"native\", \"async-api\"]"));
    assert!(CONSUMER_MANIFEST.contains("fsqlite-types = { git ="));
    assert!(
        CONSUMER_MANIFEST
            .contains("asupersync-compat = { package = \"asupersync\", version = \"=0.3.10\"")
    );
    assert!(!CONSUMER_MANIFEST.contains("[patch.crates-io]"));
    assert!(CONSUMER_LOCK.contains("name = \"asupersync-sqlite-parity-consumer\""));
    assert!(CONSUMER_LOCK.contains("name = \"fsqlite\""));
    assert_eq!(
        CONSUMER_LOCK.matches("name = \"asupersync\"").count(),
        2,
        "the consumer must resolve the current engine and pinned compatibility runtime"
    );
    assert!(CONSUMER_LOCK.contains("\"asupersync 0.3.10\""));
    assert!(CONSUMER_LOCK.contains("\"asupersync 0.4.8\""));
    assert!(CONSUMER_LOCK.contains(
        "git+https://github.com/Dicklesworthstone/frankensqlite.git?rev=92f9e9833f859ebcbe27e9fef16d9cad4372bbd7#92f9e9833f859ebcbe27e9fef16d9cad4372bbd7"
    ));
}

#[test]
fn vector_schema_is_versioned_complete_and_deterministic() {
    let vectors = parse_json(VECTORS);
    assert_eq!(vectors["schema_version"], 2);
    assert_eq!(vectors["suite_id"], "sqlite-neutral-parity-v1");
    assert_eq!(vectors["capability_id"], "CAP-SQLITE");

    let normalization = vectors["normalization"]
        .as_object()
        .expect("normalization object");
    let normalization_fields = [
        "integer",
        "real",
        "text",
        "blob",
        "null",
        "error",
        "column_order",
        "row_order",
        "pool",
        "quiescence",
    ];
    assert_eq!(
        normalization.keys().cloned().collect::<BTreeSet<_>>(),
        normalization_fields
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
    );
    assert!(normalization.values().all(|value| {
        value
            .as_str()
            .is_some_and(|description| !description.is_empty())
    }));

    let cases = vectors["vectors"].as_array().expect("vector array");
    assert_eq!(cases.len(), 6);
    let expected_vectors = [
        (
            "SQLITE-PARITY-P2-MEMORY-CONFIG-001",
            "in_memory_configuration",
        ),
        ("SQLITE-PARITY-P2-PATH-OPEN-002", "file_path_round_trip"),
        ("SQLITE-PARITY-P2-OPEN-FAILURE-003", "missing_parent_path"),
        ("SQLITE-PARITY-P2-CANCELLED-OPEN-004", "pre_cancelled_open"),
        ("SQLITE-PARITY-P2-POOL-CANCEL-005", "admission_exhaustion"),
        (
            "SQLITE-PARITY-P2-URI-UNSUPPORTED-006",
            "uri_filename_unsupported",
        ),
    ];
    for (case, (expected_id, expected_kind)) in cases.iter().zip(expected_vectors) {
        assert_eq!(case["id"], expected_id);
        assert_eq!(case["scenario"]["kind"], expected_kind);
        for field in [
            "status",
            "error_class",
            "open_state",
            "configuration_state",
            "admission_state",
            "blocking_bridge_state",
            "cancellation_state",
            "close_state",
        ] {
            assert!(
                case["expected"].get(field).is_some(),
                "missing expected.{field}"
            );
        }
        let resource = case["expected"]["resource_state"]
            .as_object()
            .expect("resource state");
        for field in [
            "connection",
            "open_transactions",
            "admission_capacity",
            "admission_available",
            "admission_waiters",
            "admission_cancellations",
            "blocking_pending",
            "blocking_busy",
            "blocking_active",
            "region_state",
            "background_work",
        ] {
            assert!(
                resource.contains_key(field),
                "missing resource_state.{field}"
            );
        }
        assert_eq!(resource["open_transactions"], 0);
        assert_eq!(resource["admission_waiters"], 0);
        assert_eq!(resource["blocking_pending"], 0);
        assert_eq!(resource["blocking_busy"], 0);
        assert_eq!(resource["blocking_active"], 0);
        assert_eq!(resource["region_state"], "closed");
        assert!(matches!(
            resource["connection"].as_str(),
            Some("closed" | "not_opened")
        ));
    }
    assert!(
        cases[..5]
            .iter()
            .all(|case| case["unsupported"].as_array().is_some_and(Vec::is_empty))
    );
    let unsupported = cases[5]["unsupported"]
        .as_array()
        .expect("URI unsupported rows");
    assert_eq!(unsupported.len(), 2);
    assert_eq!(unsupported[0]["engine"], "asupersync");
    assert_eq!(unsupported[1]["engine"], "frankensqlite");
}

#[test]
fn harness_receipt_pins_sources_profile_target_host_and_budget_defer() {
    let harness = parse_json(HARNESS);
    assert_eq!(harness["schema_version"], 5);
    assert_eq!(harness["placement"]["kind"], "neutral_standalone_consumer");
    assert_eq!(harness["placement"]["workspace_member"], false);
    assert_eq!(
        harness["placement"]["asupersync_root_has_frankensqlite_edge"],
        false
    );
    assert_eq!(
        harness["phase2"]["pins"]["frankensqlite"]["revision"],
        "92f9e9833f859ebcbe27e9fef16d9cad4372bbd7"
    );
    assert_eq!(
        harness["phase2"]["pins"]["lockfile_sha256"],
        sha256(CONSUMER_LOCK)
    );
    assert_eq!(
        harness["phase2"]["vector_contract"]["sha256"],
        sha256(VECTORS)
    );
    assert_eq!(
        harness["phase1_validation_frontier"]["status"],
        "BLOCKED_UPSTREAM_COMPILE"
    );
    for field in ["cargo_profile", "target", "host"] {
        assert!(
            harness["phase2"]["pins"][field]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "missing phase2.pins.{field}"
        );
    }
    assert_eq!(
        harness["combined_graph_budget"]["terminal_outcome"],
        "DEFER"
    );
    assert_eq!(
        harness["phase1_execution"]["clean_overlay"]["base"],
        harness["phase1_pins"]["asupersync"]["revision"]
    );
    assert_eq!(
        harness["phase1_execution"]["clean_overlay"]["no_overlay"],
        true
    );
    assert!(
        harness["phase2"]["execution"]["command"]
            .as_str()
            .is_some_and(|command| command.contains("cargo run --locked"))
    );
    assert!(
        harness["no_claims"]
            .as_array()
            .is_some_and(|rows| rows.len() >= 5)
    );
}

#[test]
fn phase3_matrix_covers_prepared_statement_boundaries_without_inventing_parity() {
    let harness = parse_json(HARNESS);
    let phase3 = &harness["phase3"];
    assert_eq!(phase3["bead_id"], "asupersync-ym2wtv.2.3");
    assert_eq!(
        phase3["status"],
        "PASS_WITH_EXPLICIT_UNEXECUTED_CROSS_ENGINE_CELLS"
    );

    let matrix = phase3["coverage_matrix"]
        .as_array()
        .expect("phase3 coverage matrix");
    assert_eq!(matrix.len(), 8);
    let boundaries = matrix
        .iter()
        .map(|row| row["boundary"].as_str().expect("boundary"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        boundaries,
        [
            "positional_binding_all_public_value_types",
            "named_placeholders_bound_by_sqlite_parameter_index",
            "cached_statement_reuse_and_reset",
            "capacity_one_cache_eviction_and_reprepare",
            "cached_statement_schema_invalidation",
            "malformed_sql_and_parameter_arity_errors",
            "statement_finalize_drop_and_pre_cancel_cleanup",
            "prepared_statement_busy_error_and_cleanup",
        ]
        .into_iter()
        .collect()
    );

    for row in matrix {
        assert_eq!(row["asupersync_status"], "PASS");
        assert!(
            row["asupersync_tests"]
                .as_array()
                .is_some_and(|tests| !tests.is_empty())
        );
        assert!(
            row["required_observations"]
                .as_array()
                .is_some_and(|observations| !observations.is_empty())
        );
        assert_ne!(row["frankensqlite_status"], "PASS");
        assert!(
            row["frankensqlite_reason"]
                .as_str()
                .is_some_and(|reason| !reason.is_empty())
        );
    }

    for test_name in [
        "sqlite_parameter_binding_boundaries",
        "sqlite_named_placeholders_bind_in_parameter_index_order",
        "sqlite_cached_statement_resets_between_bindings",
        "sqlite_malformed_and_arity_errors_release_statement_state",
        "sqlite_cached_statement_survives_schema_change",
        "sqlite_dropped_row_stream_finalizes_statement",
        "sqlite_cancelled_execute_does_not_mutate_state",
        "sqlite_busy_error_mapping_is_preserved",
    ] {
        assert!(
            PREPARED_CONFORMANCE_SOURCE.contains(&format!("fn {test_name}()")),
            "missing executable P3 conformance test {test_name}"
        );
    }
    for test_name in [
        "sqlite_prepared_statement_cache_capacity_one_reuses_evicts_and_reprepares",
        "audit_prepare_cached_statement_reuse",
    ] {
        assert!(
            SQLITE_SOURCE.contains(&format!("fn {test_name}()")),
            "missing executable P3 source test {test_name}"
        );
    }

    let conformance = &phase3["verification"]["focused_conformance"];
    assert_eq!(conformance["status"], "PASS");
    assert_eq!(conformance["passed"], 9);
    assert_eq!(conformance["failed"], 0);
    let cache_unit = &phase3["verification"]["focused_cache_unit"];
    assert_eq!(cache_unit["status"], "PASS");
    assert_eq!(cache_unit["passed"], 5);
    assert_eq!(cache_unit["failed"], 0);
}

#[test]
fn phase4_transaction_matrix_executes_both_engines_and_preserves_native_cancel_proof() {
    let harness = parse_json(HARNESS);
    let phase4 = &harness["phase4"];
    assert_eq!(phase4["bead_id"], "asupersync-ym2wtv.2.4");
    assert_eq!(
        phase4["status"],
        "PASS_BOUNDED_COMMON_MATRIX_WITH_NATIVE_CANCELLATION"
    );
    assert_eq!(phase4["consumer_source"]["sha256"], sha256(CONSUMER_SOURCE));
    assert_eq!(
        phase4["consumer_source"]["line_count"],
        CONSUMER_SOURCE.lines().count()
    );

    let expected_case_ids = [
        "SQLITE-PARITY-P4-DEFERRED-COMMIT-001",
        "SQLITE-PARITY-P4-IMMEDIATE-ROLLBACK-002",
        "SQLITE-PARITY-P4-EXCLUSIVE-COMMIT-003",
        "SQLITE-PARITY-P4-SAVEPOINT-PARTIAL-ROLLBACK-004",
        "SQLITE-PARITY-P4-CONSTRAINT-CONFLICT-RECOVERY-005",
    ];
    assert_eq!(
        phase4["neutral_matrix"]["matrix_id"],
        "sqlite-neutral-transaction-parity-v1"
    );
    assert_eq!(phase4["neutral_matrix"]["compared_cases"], 5);
    assert_eq!(
        phase4["neutral_matrix"]["case_ids"]
            .as_array()
            .expect("phase4 case IDs")
            .iter()
            .map(|value| value.as_str().expect("phase4 case ID"))
            .collect::<Vec<_>>(),
        expected_case_ids
    );

    let coverage = phase4["coverage_matrix"]
        .as_array()
        .expect("phase4 coverage matrix");
    assert_eq!(coverage.len(), 8);
    let boundaries = coverage
        .iter()
        .map(|row| row["boundary"].as_str().expect("phase4 boundary"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        boundaries,
        [
            "deferred_immediate_and_exclusive_begin_modes",
            "savepoint_partial_rollback_and_outer_commit",
            "constraint_error_preservation_rollback_and_reuse",
            "unfinished_transaction_guard_drop",
            "transaction_body_cancellation_and_physical_rollback_before_return",
            "explicit_commit_rollback_terminal_state_and_same_connection_reuse",
            "connection_state_safe_for_reuse_or_fail_closed_eviction",
            "deterministic_contention_and_runtime_quiescence",
        ]
        .into_iter()
        .collect()
    );
    assert!(coverage.iter().all(|row| {
        row["asupersync_status"]
            .as_str()
            .is_some_and(|status| status.starts_with("PASS"))
    }));
    assert!(coverage.iter().all(|row| {
        row["frankensqlite_status"]
            .as_str()
            .is_some_and(|status| status.starts_with("PASS") || status.starts_with("UNSUPPORTED"))
    }));
    for test_name in [
        "transaction_drop_rolls_back_uncommitted_work",
        "dropped_transaction_rolls_back_before_followup_connection_operation",
        "dropped_transaction_with_obligation_aborts_and_poisons",
        "busy_timeout_produces_lock_error_under_write_contention",
    ] {
        assert!(
            SQLITE_SOURCE.contains(&format!("fn {test_name}()")),
            "missing native P4 transaction test {test_name}"
        );
    }
    assert_eq!(
        coverage[3]["frankensqlite_status"],
        "UNSUPPORTED_RAII_TRANSACTION_GUARD"
    );
    assert_eq!(
        coverage[4]["frankensqlite_status"],
        "UNSUPPORTED_CLOSURE_CANCELLATION_HOOK"
    );
    assert!(
        coverage[5]["no_claim"]
            .as_str()
            .is_some_and(|text| text.contains("failure injection"))
    );
    assert!(
        coverage[6]["no_claim"]
            .as_str()
            .is_some_and(|text| text.contains("pool"))
    );

    let execution = &phase4["execution"];
    assert_eq!(execution["status"], "PASS");
    assert_eq!(execution["rch_job"], "j-29984462414544915");
    assert_eq!(execution["worker"], "ovh-a");
    assert_eq!(execution["remote_exit_code"], 0);
    assert_eq!(
        execution["overlay_paths"],
        serde_json::json!(["tests/fixtures/sqlite-parity-consumer/src/main.rs"])
    );
    assert!(
        execution["command"]
            .as_str()
            .is_some_and(|command| command.contains("cargo run --locked"))
    );

    let evidence = &execution["evidence"];
    assert_eq!(evidence["status"], "PASS");
    assert_eq!(evidence["compared_cases"], 5);
    assert_eq!(evidence["mismatches"].as_array().map(Vec::len), Some(0));
    let asupersync = evidence["asupersync"]
        .as_array()
        .expect("asupersync P4 evidence");
    let frankensqlite = evidence["frankensqlite"]
        .as_array()
        .expect("FrankenSQLite P4 evidence");
    assert_eq!(asupersync.len(), expected_case_ids.len());
    assert_eq!(asupersync, frankensqlite);
    for (row, expected_id) in asupersync.iter().zip(expected_case_ids) {
        assert_eq!(row["case_id"], expected_id);
        assert_eq!(row["connection_reusable"], true);
        assert_eq!(row["open_transactions"], 0);
    }
    assert_eq!(asupersync[0]["terminal_state"], "committed");
    assert_eq!(
        asupersync[0]["visible_labels"],
        serde_json::json!(["deferred"])
    );
    assert_eq!(asupersync[1]["terminal_state"], "rolled_back");
    assert_eq!(asupersync[1]["visible_labels"], serde_json::json!([]));
    assert_eq!(asupersync[2]["terminal_state"], "committed");
    assert_eq!(
        asupersync[2]["visible_labels"],
        serde_json::json!(["exclusive"])
    );
    assert_eq!(
        asupersync[3]["terminal_state"],
        "committed_after_savepoint_rollback"
    );
    assert_eq!(
        asupersync[3]["visible_labels"],
        serde_json::json!(["base", "after"])
    );
    assert_eq!(
        asupersync[4]["terminal_state"],
        "constraint_rejected_then_recovered"
    );
    assert_eq!(asupersync[4]["visible_labels"], serde_json::json!([]));
    assert_eq!(asupersync[4]["conflict_class"], "constraint_violation");

    for marker in [
        "fn run_asupersync_transaction_cases(",
        "fn run_frankensqlite_transaction_cases(",
        "SqliteSavepoint::new",
        "is_constraint_violation()",
        "is_franken_constraint_conflict",
        "require_runtime_quiescence(&blocking, \"asupersync transaction matrix\")",
        "require_compat_runtime_quiescence(&blocking, \"FrankenSQLite transaction matrix\")",
    ] {
        assert!(
            CONSUMER_SOURCE.contains(marker),
            "missing executable P4 consumer marker {marker}"
        );
    }
    for test_name in [
        "sqlite_real_disk_cancel_during_tx_body_rolls_back_and_leaves_file_consistent",
        "sqlite_real_disk_cancel_during_immediate_tx_rolls_back_before_return",
    ] {
        assert!(
            REAL_DISK_CANCEL_ROLLBACK_SOURCE.contains(&format!("fn {test_name}()")),
            "missing native P4 cancellation test {test_name}"
        );
    }
    assert!(REAL_DISK_CANCEL_ROLLBACK_SOURCE.contains("busy_timeout(Duration::ZERO)"));
    assert!(
        phase4["no_claims"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|row| row
                .as_str()
                .is_some_and(|text| text.contains("does not authorize dependency cutover"))))
    );
}

#[test]
fn phase5_matrix_covers_every_race_boundary_without_inventing_cross_engine_support() {
    let harness = parse_json(HARNESS);
    let phase5 = &harness["phase5"];
    assert_eq!(phase5["bead_id"], "asupersync-ym2wtv.2.5");
    assert_eq!(
        phase5["status"],
        "PASS_WITH_EXPLICIT_UNSUPPORTED_CROSS_ENGINE_CELLS"
    );

    let matrix = phase5["coverage_matrix"]
        .as_array()
        .expect("phase5 coverage matrix");
    assert_eq!(matrix.len(), 8);
    let boundaries = matrix
        .iter()
        .map(|row| row["boundary"].as_str().expect("boundary"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        boundaries,
        [
            "queued_operation_cancellation",
            "queued_row_stream_cancellation",
            "result_channel_reserve_cancellation",
            "running_statement_cancellation",
            "committed_result_vs_late_cancellation",
            "statement_and_row_stream_timeout",
            "explicit_native_interrupt",
            "connection_and_runtime_shutdown",
        ]
        .into_iter()
        .collect()
    );

    for row in matrix {
        assert_eq!(row["asupersync_status"], "PASS");
        assert!(
            row["asupersync_tests"]
                .as_array()
                .is_some_and(|tests| !tests.is_empty())
        );
        assert!(
            row["required_observations"]
                .as_array()
                .is_some_and(|observations| !observations.is_empty())
        );
        assert!(
            row["frankensqlite_status"]
                .as_str()
                .is_some_and(|status| !status.is_empty())
        );
        assert!(
            row["frankensqlite_reason"]
                .as_str()
                .is_some_and(|reason| !reason.is_empty())
        );
    }

    for test_name in [
        "sqlite_p5_queued_cancel_does_not_interrupt_connection_owner",
        "sqlite_p5_queued_stream_cancel_does_not_interrupt_connection_owner",
        "sqlite_p5_reserve_race_cancellation_does_not_execute_operation",
        "cancel_interrupts_in_flight_statement_and_drains",
        "sqlite_p5_committed_result_wins_finishing_cancellation",
        "statement_timeout_override_aborts_runaway_query",
        "row_stream_statement_timeout_aborts_runaway_query",
        "sqlite_p5_explicit_interrupt_stops_statement_and_preserves_connection",
    ] {
        assert!(
            SQLITE_SOURCE.contains(&format!("fn {test_name}()")),
            "missing executable P5 test {test_name}"
        );
    }
    assert!(SQLITE_SOURCE.contains("pub fn interrupt(&self)"));

    let focused = &phase5["verification"]["focused"];
    assert_eq!(focused["status"], "PASS");
    assert_eq!(focused["passed"], 5);
    assert_eq!(focused["failed"], 0);
    let module = &phase5["verification"]["serialized_sqlite_module"];
    assert_eq!(module["status"], "PASS");
    assert_eq!(module["passed"], 121);
    assert_eq!(module["failed"], 0);
}

#[test]
fn phase6_value_row_matrix_executes_common_values_and_records_metadata_limit() {
    let harness = parse_json(HARNESS);
    let phase6 = &harness["phase6"];
    assert_eq!(phase6["bead_id"], "asupersync-ym2wtv.2.6");
    assert_eq!(
        phase6["status"],
        "PASS_BOUNDED_COMMON_VALUES_WITH_EXPLICIT_ROW_METADATA_UNSUPPORTED"
    );
    assert_eq!(phase6["consumer_source"]["sha256"], sha256(CONSUMER_SOURCE));
    assert_eq!(
        phase6["consumer_source"]["line_count"],
        CONSUMER_SOURCE.lines().count()
    );

    let expected_case_ids = [
        "SQLITE-PARITY-P6-NULL-001",
        "SQLITE-PARITY-P6-I64-MIN-002",
        "SQLITE-PARITY-P6-I64-MAX-003",
        "SQLITE-PARITY-P6-I64-BEYOND-EXACT-F64-004",
        "SQLITE-PARITY-P6-NEGATIVE-ZERO-005",
        "SQLITE-PARITY-P6-POSITIVE-INFINITY-006",
        "SQLITE-PARITY-P6-NEGATIVE-INFINITY-007",
        "SQLITE-PARITY-P6-NAN-TO-NULL-008",
        "SQLITE-PARITY-P6-EMPTY-TEXT-009",
        "SQLITE-PARITY-P6-UNICODE-NUL-TEXT-010",
        "SQLITE-PARITY-P6-EMPTY-BLOB-011",
        "SQLITE-PARITY-P6-BINARY-BLOB-012",
        "SQLITE-PARITY-P6-LARGE-TEXT-013",
        "SQLITE-PARITY-P6-LARGE-BLOB-014",
    ];
    let matrix = &phase6["neutral_matrix"];
    assert_eq!(matrix["matrix_id"], "sqlite-neutral-value-row-parity-v1");
    assert_eq!(matrix["profile_max_value_bytes"], 1024 * 1024);
    assert_eq!(matrix["compared_values"], expected_case_ids.len());
    assert_eq!(
        matrix["case_ids"]
            .as_array()
            .expect("phase6 case IDs")
            .iter()
            .map(|value| value.as_str().expect("phase6 case ID"))
            .collect::<Vec<_>>(),
        expected_case_ids
    );
    for case_id in expected_case_ids {
        assert!(
            CONSUMER_SOURCE.contains(case_id),
            "missing executable P6 case {case_id}"
        );
    }

    let coverage = phase6["coverage_matrix"]
        .as_array()
        .expect("phase6 coverage matrix");
    assert_eq!(coverage.len(), 6);
    assert!(
        coverage
            .iter()
            .all(|row| row["asupersync_status"] == "PASS")
    );
    assert_eq!(
        coverage[4]["boundary"],
        "ordered_duplicate_preserving_column_metadata_and_name_lookup"
    );
    assert_eq!(
        coverage[4]["frankensqlite_status"],
        "UNSUPPORTED_NO_PUBLIC_ASYNC_ROW_METADATA"
    );
    assert!(
        coverage[4]["frankensqlite_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("does not infer aliases"))
    );

    let execution = &phase6["execution"];
    assert_eq!(execution["status"], "PASS");
    assert_eq!(execution["rch_job"], "j-29984462414544922");
    assert_eq!(execution["worker"], "vmi1153651");
    assert_eq!(execution["remote_exit_code"], 0);
    assert_eq!(
        execution["overlay_paths"],
        serde_json::json!(["tests/fixtures/sqlite-parity-consumer/src/main.rs"])
    );
    let evidence = &execution["evidence_summary"];
    assert_eq!(evidence["compared_values"], expected_case_ids.len());
    assert_eq!(evidence["mismatches"].as_array().map(Vec::len), Some(0));
    assert_eq!(evidence["asupersync_owned_after_close"], true);
    assert_eq!(evidence["frankensqlite_owned_after_close"], true);
    assert_eq!(evidence["asupersync_runtime_quiescent"], true);
    assert_eq!(evidence["frankensqlite_runtime_quiescent"], true);
    assert_eq!(evidence["asupersync_type_mismatch_class"], "type_mismatch");
    assert_eq!(
        evidence["frankensqlite_type_mismatch_class"],
        "type_mismatch"
    );
    assert_eq!(
        evidence["asupersync_out_of_bounds_class"],
        "index_out_of_bounds"
    );
    assert_eq!(
        evidence["frankensqlite_out_of_bounds_class"],
        "index_out_of_bounds"
    );
    assert_eq!(evidence["large_text"]["byte_len"], 1024 * 1024);
    assert_eq!(evidence["large_text"]["fnv1a64"], "73833fad05222325");
    assert_eq!(evidence["large_blob"]["byte_len"], 1024 * 1024);
    assert_eq!(evidence["large_blob"]["fnv1a64"], "1f5e0df9bc822325");
    assert_eq!(
        evidence["asupersync_row_metadata"]["ordered_names"],
        serde_json::json!(["dup", "Other", "dup", "Tail"])
    );
    assert_eq!(
        evidence["asupersync_row_metadata"]["legacy_sorted_unique_names"],
        serde_json::json!(["Other", "Tail", "dup"])
    );
    assert_eq!(
        evidence["asupersync_row_metadata"]["first_ascii_case_insensitive_dup_index"],
        0
    );
    assert_eq!(
        evidence["asupersync_row_metadata"]["legacy_exact_dup_value"],
        3
    );
    assert_eq!(
        evidence["asupersync_row_metadata"]["missing_name_class"],
        "column_not_found"
    );
    assert_eq!(
        evidence["frankensqlite_row_metadata_status"],
        "UNSUPPORTED_NO_PUBLIC_ASYNC_ROW_METADATA"
    );

    for marker in [
        "fn run_asupersync_value_matrix(",
        "fn run_frankensqlite_value_matrix(",
        "f64::NAN",
        "column_names_in_order()",
        "require_runtime_quiescence(&blocking, \"asupersync-p6\")",
        "require_compat_runtime_quiescence(&blocking, \"frankensqlite-p6\")",
    ] {
        assert!(
            CONSUMER_SOURCE.contains(marker),
            "missing executable P6 consumer marker {marker}"
        );
    }
}

#[test]
fn phase7_checked_sql_policy_is_machine_readable_reused_and_adversarial() {
    let harness = parse_json(HARNESS);
    let phase7 = &harness["phase7"];
    assert_eq!(phase7["bead_id"], "asupersync-ym2wtv.2.7");
    assert_eq!(phase7["status"], "PASS");
    assert_eq!(
        phase7["policy"]["policy_id"],
        "sqlite-checked-sql-policy-v1"
    );
    assert_eq!(phase7["policy"]["maximum_sql_bytes"], 1024 * 1024);
    assert_eq!(phase7["policy"]["maximum_parser_recursion"], 128);
    assert_eq!(
        phase7["policy"]["parameter_policy"],
        "BOUND_VALUES_ARE_DATA_AND_ARE_NEVER_REPARSED_AS_SQL_SYNTAX"
    );

    let deny_rules = phase7["policy"]["deny_rules"]
        .as_array()
        .expect("phase7 deny rules");
    assert_eq!(deny_rules.len(), 8);
    assert!(deny_rules.iter().all(|rule| rule["decision"] == "DENY"));
    let deny_classes = deny_rules
        .iter()
        .map(|rule| rule["class"].as_str().expect("deny class"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        deny_classes,
        [
            "parser_rejected",
            "byte_or_recursion_limit",
            "single_statement_count_not_one",
            "pragma",
            "transaction_or_connection_control",
            "attach_or_detach",
            "vacuum_or_vacuum_into",
            "load_extension_call",
        ]
        .into_iter()
        .collect()
    );

    let entries = phase7["public_entry_points"]
        .as_array()
        .expect("checked entry points");
    assert_eq!(entries.len(), 7);
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry["api"].as_str().expect("entry point"))
            .collect::<BTreeSet<_>>(),
        [
            "SqliteConnection::execute",
            "SqliteConnection::execute_batch",
            "SqliteConnection::query",
            "SqliteConnection::query_row",
            "SqliteConnection::query_stream",
            "SqliteTransaction::execute",
            "SqliteTransaction::query",
        ]
        .into_iter()
        .collect()
    );
    assert!(SQLITE_SOURCE.contains("pub fn validate_checked_sql_statement"));
    assert!(SQLITE_SOURCE.contains("pub fn validate_checked_sql_batch"));
    assert!(SQLITE_SOURCE.contains("SqlSurfaceViolation::ExtensionLoading"));
    assert_eq!(
        SQLITE_SOURCE
            .matches("if let Err(err) = validate_checked_sql_statement(sql)")
            .count(),
        4,
        "all four checked single-statement entry points must reuse the public validator"
    );
    assert_eq!(
        SQLITE_SOURCE
            .matches("if let Err(err) = validate_checked_sql_batch(sql)")
            .count(),
        1,
        "the checked batch entry point must reuse the public batch validator"
    );
    assert_eq!(
        SQLITE_SOURCE
            .matches("self.conn.execute(cx, sql, params).await")
            .count(),
        1,
        "transaction execute must delegate to the checked connection entry point"
    );
    assert_eq!(
        SQLITE_SOURCE
            .matches("self.conn.query(cx, sql, params).await")
            .count(),
        1,
        "transaction query must delegate to the checked connection entry point"
    );
    assert!(
        SQLITE_SOURCE
            .contains("fn every_checked_public_entry_point_applies_the_same_fail_closed_policy")
    );

    let case_ids = phase7["neutral_adapter"]["case_ids"]
        .as_array()
        .expect("phase7 case ids");
    assert_eq!(case_ids.len(), 13);
    assert_eq!(
        case_ids
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>()
            .len(),
        13
    );
    for case_id in case_ids.iter().filter_map(Value::as_str) {
        assert!(
            CONSUMER_SOURCE.contains(case_id),
            "neutral consumer is missing {case_id}"
        );
    }
    for marker in [
        "validate_checked_sql_statement(&case.sql)",
        "run_asupersync_security_cases",
        "run_frankensqlite_security_cases",
        "require_runtime_quiescence",
        "require_compat_runtime_quiescence",
    ] {
        assert!(
            CONSUMER_SOURCE.contains(marker),
            "neutral consumer is missing {marker}"
        );
    }

    assert_eq!(phase7["bounded_fuzz"]["deterministic_cases"], 4096);
    assert!(SQLITE_SOURCE.contains("fn checked_sql_policy_bounded_adversarial_fuzz_is_panic_free"));
    for lane in ["sqlite_module", "neutral_consumer", "repository_contract"] {
        assert_eq!(phase7["verification"][lane]["status"], "PASS");
        assert!(
            phase7["verification"][lane]["rch_job"]
                .as_str()
                .is_some_and(|job| !job.is_empty()),
            "phase7 verification lane {lane} lacks an RCH receipt"
        );
    }
}

#[test]
fn clean_phase2_execution_receipt_matches_all_declared_vectors() {
    let harness = parse_json(HARNESS);
    assert_eq!(harness["phase1_execution"]["status"], "PASS");
    assert_eq!(harness["phase2"]["execution"]["status"], "PASS");
    let evidence = &harness["phase2"]["execution"]["evidence"];
    assert_eq!(evidence["evidence_schema_version"], 1);
    assert_eq!(evidence["vector_schema_version"], 2);
    assert_eq!(evidence["suite_id"], "sqlite-neutral-parity-v1");
    assert_eq!(evidence["capability_id"], "CAP-SQLITE");
    assert_eq!(
        evidence["provenance"]["asupersync_revision"],
        harness["phase2"]["pins"]["asupersync"]["revision"]
    );
    assert_eq!(
        evidence["provenance"]["frankensqlite_revision"],
        harness["phase2"]["pins"]["frankensqlite"]["revision"]
    );
    assert_eq!(evidence["comparison"]["comparable"], true);
    assert_eq!(evidence["comparison"]["compared_vectors"], 6);
    assert_eq!(
        evidence["comparison"]["mismatches"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );

    let engines = evidence["engine_results"]
        .as_array()
        .expect("engine evidence");
    assert_eq!(engines.len(), 2);
    assert_eq!(engines[0]["engine"], "asupersync");
    assert_eq!(engines[1]["engine"], "frankensqlite");
    assert_eq!(engines[0]["vectors"].as_array().map(Vec::len), Some(6));
    assert_eq!(engines[1]["vectors"].as_array().map(Vec::len), Some(6));
    for (asupersync, frankensqlite) in engines[0]["vectors"]
        .as_array()
        .expect("asupersync vector evidence")
        .iter()
        .zip(
            engines[1]["vectors"]
                .as_array()
                .expect("FrankenSQLite vector evidence"),
        )
    {
        assert_eq!(asupersync["vector_id"], frankensqlite["vector_id"]);
        assert_eq!(asupersync["outcome"], frankensqlite["outcome"]);
        let resource = &asupersync["outcome"]["resource_state"];
        assert_eq!(resource["open_transactions"], 0);
        assert_eq!(resource["admission_waiters"], 0);
        assert_eq!(resource["blocking_pending"], 0);
        assert_eq!(resource["blocking_busy"], 0);
        assert_eq!(resource["blocking_active"], 0);
        assert_eq!(resource["region_state"], "closed");
        assert_eq!(
            resource["background_work"],
            "none_observed_after_runtime_shutdown"
        );
    }
}

#[test]
fn operator_doc_preserves_reproduction_and_no_claim_boundaries() {
    for marker in [
        "neutral consumer",
        "independent `Cargo.lock`",
        "SQLITE-PARITY-P2-POOL-CANCEL-005",
        "consumer-owned admission semaphore",
        "ASUPERSYNC_SOURCE_REVISION=<source-commit>",
        "cargo run --locked",
        "terminal `DEFER`",
        "does not authorize dependency cutover",
        "SQLite P3 prepared-statement matrix",
        "Full P3 parity",
        "SQLite P4 transaction and savepoint matrix",
        "constraint-conflict recovery",
        "native cancellation evidence",
        "SQLite P5 cancellation matrix",
        "unsupported cells stay unsupported",
        "SQLite P6 value and row matrix",
        "1 MiB",
        "UNSUPPORTED_NO_PUBLIC_ASYNC_ROW_METADATA",
        "SQLite P7 checked-SQL security parity",
        "validate_checked_sql_statement",
        "4,096 bounded variants",
    ] {
        assert!(
            DOC.contains(marker),
            "missing documentation marker {marker}"
        );
    }
}
