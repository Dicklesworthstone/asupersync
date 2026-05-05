//! Contract tests for the WASM E2E log schema and artifact bundle layout
//! (asupersync-3qv04.8.4.4).
//!
//! Validates the schema artifact, log entry structure, artifact bundle layout,
//! retention policy, error code taxonomy, and cross-references to the evidence matrix.

use std::collections::HashSet;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_schema() -> serde_json::Value {
    let path = repo_root().join("artifacts/wasm_e2e_log_schema_v1.json");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    serde_json::from_str(&content).expect("invalid JSON in log schema artifact")
}

// ── Schema Structure ─────────────────────────────────────────────────

#[test]
fn schema_artifact_exists_and_has_version() {
    let schema = load_schema();
    assert_eq!(
        schema["schema_version"].as_str().unwrap(),
        "wasm-e2e-log-schema-v1"
    );
    assert_eq!(
        schema["bead_id"].as_str().unwrap(),
        "asupersync-3qv04.8.4.4"
    );
}

#[test]
fn schema_doc_exists() {
    let path = repo_root().join("docs/wasm_e2e_log_schema.md");
    assert!(path.exists(), "missing log schema doc");
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("wasm-e2e-log-schema-v1"));
    assert!(content.contains("scenario_id"));
    assert!(content.contains("run_id"));
}

// ── Log Entry Schema ─────────────────────────────────────────────────

#[test]
fn log_entry_has_required_fields() {
    let schema = load_schema();
    let required = schema["log_entry"]["required_fields"]
        .as_array()
        .expect("required_fields must be array");

    let names: Vec<&str> = required.iter().filter_map(|f| f["name"].as_str()).collect();

    for expected in &["ts", "level", "scenario_id", "run_id", "event", "msg"] {
        assert!(
            names.contains(expected),
            "required field {expected} missing from log entry schema"
        );
    }
}

#[test]
fn log_entry_has_optional_fields() {
    let schema = load_schema();
    let optional = schema["log_entry"]["optional_fields"]
        .as_array()
        .expect("optional_fields must be array");

    let names: Vec<&str> = optional.iter().filter_map(|f| f["name"].as_str()).collect();

    for expected in &[
        "abi_version",
        "abi_fingerprint",
        "browser",
        "build",
        "duration_ms",
        "stack_trace",
        "error_code",
        "evidence_ids",
    ] {
        assert!(
            names.contains(expected),
            "optional field {expected} missing from log entry schema"
        );
    }
}

#[test]
fn log_entry_ts_field_is_iso8601() {
    let schema = load_schema();
    let required = schema["log_entry"]["required_fields"].as_array().unwrap();
    let ts_field = required.iter().find(|f| f["name"] == "ts").unwrap();
    assert_eq!(ts_field["format"].as_str().unwrap(), "ISO-8601");
}

// ── Log Levels ───────────────────────────────────────────────────────

#[test]
fn log_levels_are_complete() {
    let schema = load_schema();
    let levels: Vec<&str> = schema["log_levels"]
        .as_array()
        .expect("log_levels must be array")
        .iter()
        .filter_map(|l| l.as_str())
        .collect();

    for expected in &["trace", "debug", "info", "warn", "error", "fatal"] {
        assert!(levels.contains(expected), "missing log level: {expected}");
    }
}

#[test]
fn log_levels_are_ordered_by_severity() {
    let schema = load_schema();
    let levels: Vec<&str> = schema["log_levels"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|l| l.as_str())
        .collect();

    let expected_order = ["trace", "debug", "info", "warn", "error", "fatal"];
    assert_eq!(
        levels, expected_order,
        "log levels must be ordered by severity"
    );
}

// ── Verdicts ─────────────────────────────────────────────────────────

#[test]
fn verdicts_are_complete() {
    let schema = load_schema();
    let verdicts: Vec<&str> = schema["verdicts"]
        .as_array()
        .expect("verdicts must be array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();

    for expected in &["pass", "fail", "error", "timeout", "skip"] {
        assert!(verdicts.contains(expected), "missing verdict: {expected}");
    }
}

// ── Error Code Taxonomy ──────────────────────────────────────────────

#[test]
fn error_codes_exist_and_have_required_fields() {
    let schema = load_schema();
    let codes = schema["error_codes"]
        .as_array()
        .expect("error_codes must be array");

    assert!(codes.len() >= 5, "must define at least 5 error codes");

    for code in codes {
        assert!(
            code["code"].as_str().is_some(),
            "error code missing 'code' field"
        );
        assert!(
            code["category"].as_str().is_some(),
            "error code missing 'category' field"
        );
        assert!(
            code["description"].as_str().is_some(),
            "error code missing 'description' field"
        );
    }
}

#[test]
fn error_codes_are_unique() {
    let schema = load_schema();
    let codes: Vec<&str> = schema["error_codes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["code"].as_str())
        .collect();

    let unique: HashSet<&str> = codes.iter().copied().collect();
    assert_eq!(codes.len(), unique.len(), "duplicate error codes found");
}

#[test]
fn error_codes_cover_key_categories() {
    let schema = load_schema();
    let categories: HashSet<&str> = schema["error_codes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["category"].as_str())
        .collect();

    for expected in &[
        "compatibility",
        "bridge",
        "lifecycle",
        "test",
        "infrastructure",
    ] {
        assert!(
            categories.contains(expected),
            "missing error category: {expected}"
        );
    }
}

#[test]
fn error_codes_include_critical_codes() {
    let schema = load_schema();
    let codes: HashSet<&str> = schema["error_codes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["code"].as_str())
        .collect();

    for expected in &[
        "ABI_MISMATCH",
        "BRIDGE_TIMEOUT",
        "HANDLE_LEAK",
        "ASSERTION_FAIL",
        "WASM_TRAP",
    ] {
        assert!(
            codes.contains(expected),
            "missing critical error code: {expected}"
        );
    }
}

// ── Artifact Bundle Layout ───────────────────────────────────────────

#[test]
fn artifact_bundle_has_directory_layout() {
    let schema = load_schema();
    let bundle = &schema["artifact_bundle"];
    assert_eq!(
        bundle["schema_version"].as_str().unwrap(),
        "wasm-e2e-artifact-bundle-v1"
    );

    let layout = &bundle["directory_layout"];
    assert!(
        layout["root"].as_str().unwrap().contains("{scenario_id}"),
        "bundle root must include scenario_id template"
    );
    assert!(
        layout["root"].as_str().unwrap().contains("{run_id}"),
        "bundle root must include run_id template"
    );
}

#[test]
fn artifact_bundle_has_required_files() {
    let schema = load_schema();
    let files = schema["artifact_bundle"]["directory_layout"]["files"]
        .as_array()
        .expect("files must be array");

    let required_paths: Vec<&str> = files
        .iter()
        .filter(|f| f["required"] == true)
        .filter_map(|f| f["path"].as_str())
        .collect();

    assert!(
        required_paths.contains(&"run-metadata.json"),
        "run-metadata.json must be required"
    );
    assert!(
        required_paths.contains(&"log.jsonl"),
        "log.jsonl must be required"
    );
}

#[test]
fn artifact_bundle_naming_has_patterns() {
    let schema = load_schema();
    let naming = &schema["artifact_bundle"]["naming"];
    assert!(
        naming["scenario_id_pattern"].as_str().is_some(),
        "must define scenario_id pattern"
    );
    assert!(
        naming["run_id_format"].as_str().is_some(),
        "must define run_id format"
    );
}

// ── Run Metadata ─────────────────────────────────────────────────────

#[test]
fn run_metadata_has_required_fields() {
    let schema = load_schema();
    let meta = &schema["run_metadata"];
    assert_eq!(
        meta["schema_version"].as_str().unwrap(),
        "wasm-e2e-run-metadata-v1"
    );

    let required: Vec<&str> = meta["required_fields"]
        .as_array()
        .expect("required_fields must be array")
        .iter()
        .filter_map(|f| f.as_str())
        .collect();

    for expected in &[
        "scenario_id",
        "run_id",
        "started_at",
        "finished_at",
        "duration_ms",
        "verdict",
        "browser",
        "build",
        "abi_version",
        "abi_fingerprint",
    ] {
        assert!(
            required.contains(expected),
            "run metadata missing required field: {expected}"
        );
    }
}

// ── Retention Policy ─────────────────────────────────────────────────

#[test]
fn retention_policy_has_three_classes() {
    let schema = load_schema();
    let classes = schema["retention_policy"]["classes"]
        .as_array()
        .expect("retention classes must be array");

    assert_eq!(classes.len(), 3, "must have exactly 3 retention classes");

    let names: Vec<&str> = classes.iter().filter_map(|c| c["class"].as_str()).collect();
    assert!(names.contains(&"hot"));
    assert!(names.contains(&"warm"));
    assert!(names.contains(&"cold"));
}

#[test]
fn retention_classes_have_min_days() {
    let schema = load_schema();
    let classes = schema["retention_policy"]["classes"].as_array().unwrap();

    for class in classes {
        let name = class["class"].as_str().unwrap();
        let days = class["min_days"].as_u64().expect("min_days must be u64");
        assert!(days > 0, "retention class {name} must have min_days > 0");
    }
}

#[test]
fn retention_hot_longer_than_warm_longer_than_cold() {
    let schema = load_schema();
    let classes = schema["retention_policy"]["classes"].as_array().unwrap();

    let hot_days = classes.iter().find(|c| c["class"] == "hot").unwrap()["min_days"]
        .as_u64()
        .unwrap();
    let warm_days = classes.iter().find(|c| c["class"] == "warm").unwrap()["min_days"]
        .as_u64()
        .unwrap();
    let cold_days = classes.iter().find(|c| c["class"] == "cold").unwrap()["min_days"]
        .as_u64()
        .unwrap();

    assert!(
        hot_days > warm_days,
        "hot ({hot_days}) must be longer than warm ({warm_days})"
    );
    assert!(
        warm_days > cold_days,
        "warm ({warm_days}) must be longer than cold ({cold_days})"
    );
}

// ── Cross-Reference to Evidence Matrix ───────────────────────────────

#[test]
fn evidence_matrix_references_log_schema_version() {
    let path = repo_root().join("artifacts/wasm_qa_evidence_matrix_v1.json");
    let content = std::fs::read_to_string(&path).unwrap();
    let matrix: serde_json::Value = serde_json::from_str(&content).unwrap();

    assert_eq!(
        matrix["e2e_log_schema_version"].as_str().unwrap(),
        "wasm-qa-e2e-log-v1",
        "evidence matrix must reference the E2E log schema version"
    );
}

#[test]
fn evidence_matrix_retention_aligns_with_log_schema() {
    let matrix_path = repo_root().join("artifacts/wasm_qa_evidence_matrix_v1.json");
    let matrix: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&matrix_path).unwrap()).unwrap();

    let schema = load_schema();

    // Both must define the same retention class names
    let matrix_classes: HashSet<&str> = matrix["retention_policy"]["classes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["class"].as_str())
        .collect();

    let schema_classes: HashSet<&str> = schema["retention_policy"]["classes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["class"].as_str())
        .collect();

    assert_eq!(
        matrix_classes, schema_classes,
        "retention class names must match between evidence matrix and log schema"
    );
}

// ── Schema Completeness ──────────────────────────────────────────────

#[test]
fn all_log_entry_fields_have_type_and_description() {
    let schema = load_schema();

    for section in &["required_fields", "optional_fields"] {
        let fields = schema["log_entry"][section].as_array().unwrap();
        for field in fields {
            let name = field["name"].as_str().unwrap();
            assert!(
                field["type"].as_str().is_some(),
                "field {name} in {section} missing type"
            );
            assert!(
                field["description"].as_str().is_some(),
                "field {name} in {section} missing description"
            );
        }
    }
}

#[test]
fn no_duplicate_field_names_across_required_and_optional() {
    let schema = load_schema();

    let mut all_names: Vec<String> = Vec::new();
    for section in &["required_fields", "optional_fields"] {
        for field in schema["log_entry"][section].as_array().unwrap() {
            all_names.push(field["name"].as_str().unwrap().to_string());
        }
    }

    let unique: HashSet<&str> = all_names.iter().map(std::string::String::as_str).collect();
    assert_eq!(
        all_names.len(),
        unique.len(),
        "duplicate field names found in log entry schema"
    );
}
