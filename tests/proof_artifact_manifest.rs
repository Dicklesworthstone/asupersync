//! Proof artifact manifest format validation (bd-2rhiq).
//!
//! Validates that the proof runner (scripts/run_proof_checks.sh) produces
//! a well-formed manifest.json conforming to the expected schema.
//!
//! The manifest schema is:
//!   {
//!     "version": "1.0.0",
//!     "bead": string,
//!     "started_at": ISO-8601,
//!     "finished_at": ISO-8601,
//!     "git_sha": string,
//!     "git_branch": string,
//!     "total": u32,
//!     "passed": u32,
//!     "failed": u32,
//!     "skipped": u32,
//!     "status": "pass" | "fail",
//!     "checks": [
//!       {
//!         "name": string,
//!         "category": string,
//!         "status": "pass" | "fail" | "skip",
//!         "elapsed_s": u32,
//!         "log": string
//!       }
//!     ]
//!   }
//!
//! Cross-references:
//!   Proof runner: scripts/run_proof_checks.sh
//!   CI workflow:  .github/workflows/ci.yml (proof-checks job)

use serde_json::Value;

/// Validate a manifest JSON value against the expected schema.
fn validate_manifest(manifest: &Value) -> Vec<String> {
    let mut errors = Vec::new();

    // Required top-level fields
    let required_strings = ["version", "bead", "started_at", "finished_at", "git_sha", "git_branch", "status"];
    for field in &required_strings {
        match manifest.get(field) {
            Some(Value::String(_)) => {}
            Some(other) => errors.push(format!("'{field}' should be string, got {}", other)),
            None => errors.push(format!("missing required field '{field}'")),
        }
    }

    let required_numbers = ["total", "passed", "failed", "skipped"];
    for field in &required_numbers {
        match manifest.get(field) {
            Some(Value::Number(_)) => {}
            Some(other) => errors.push(format!("'{field}' should be number, got {}", other)),
            None => errors.push(format!("missing required field '{field}'")),
        }
    }

    // Version must be semver-ish
    if let Some(Value::String(v)) = manifest.get("version") {
        let parts: Vec<&str> = v.split('.').collect();
        if parts.len() != 3 || parts.iter().any(|p| p.parse::<u32>().is_err()) {
            errors.push(format!("'version' should be semver (got '{v}')"));
        }
    }

    // Status must be "pass" or "fail"
    if let Some(Value::String(s)) = manifest.get("status") {
        if s != "pass" && s != "fail" {
            errors.push(format!("'status' must be 'pass' or 'fail' (got '{s}')"));
        }
    }

    // Arithmetic consistency: total = passed + failed + skipped
    if let (Some(total), Some(passed), Some(failed), Some(skipped)) = (
        manifest.get("total").and_then(Value::as_u64),
        manifest.get("passed").and_then(Value::as_u64),
        manifest.get("failed").and_then(Value::as_u64),
        manifest.get("skipped").and_then(Value::as_u64),
    ) {
        if total != passed + failed + skipped {
            errors.push(format!(
                "total ({total}) != passed ({passed}) + failed ({failed}) + skipped ({skipped})"
            ));
        }
    }

    // Checks array
    match manifest.get("checks") {
        Some(Value::Array(checks)) => {
            for (i, check) in checks.iter().enumerate() {
                let check_required_strings = ["name", "category", "status", "log"];
                for field in &check_required_strings {
                    match check.get(field) {
                        Some(Value::String(_)) => {}
                        Some(other) => errors.push(format!("checks[{i}].'{field}' should be string, got {other}")),
                        None => errors.push(format!("checks[{i}] missing required field '{field}'")),
                    }
                }

                // elapsed_s must be a number
                match check.get("elapsed_s") {
                    Some(Value::Number(_)) => {}
                    Some(other) => errors.push(format!("checks[{i}].'elapsed_s' should be number, got {other}")),
                    None => errors.push(format!("checks[{i}] missing required field 'elapsed_s'")),
                }

                // Check status values
                if let Some(Value::String(s)) = check.get("status") {
                    if s != "pass" && s != "fail" && s != "skip" {
                        errors.push(format!(
                            "checks[{i}].'status' must be pass/fail/skip (got '{s}')"
                        ));
                    }
                }
            }
        }
        Some(other) => errors.push(format!("'checks' should be array, got {other}")),
        None => errors.push("missing required field 'checks'".to_string()),
    }

    errors
}

#[test]
fn manifest_schema_valid_pass() {
    let manifest: Value = serde_json::from_str(
        r#"{
            "version": "1.0.0",
            "bead": "bd-2rhiq",
            "started_at": "2026-02-04T06:00:00Z",
            "finished_at": "2026-02-04T06:05:00Z",
            "git_sha": "abc1234",
            "git_branch": "main",
            "total": 3,
            "passed": 2,
            "failed": 0,
            "skipped": 1,
            "status": "pass",
            "checks": [
                {"name": "Certificate verification", "category": "rust-proofs", "status": "pass", "elapsed_s": 5, "log": "certificate_verification.log"},
                {"name": "Obligation formal checks", "category": "rust-proofs", "status": "pass", "elapsed_s": 3, "log": "obligation_formal_checks.log"},
                {"name": "Lean proof build", "category": "lean-proofs", "status": "skip", "elapsed_s": 0, "log": ""}
            ]
        }"#,
    )
    .expect("valid JSON");

    let errors = validate_manifest(&manifest);
    assert!(errors.is_empty(), "unexpected validation errors: {:?}", errors);
}

#[test]
fn manifest_schema_valid_fail() {
    let manifest: Value = serde_json::from_str(
        r#"{
            "version": "1.0.0",
            "bead": "bd-2rhiq",
            "started_at": "2026-02-04T06:00:00Z",
            "finished_at": "2026-02-04T06:05:00Z",
            "git_sha": "abc1234",
            "git_branch": "main",
            "total": 2,
            "passed": 1,
            "failed": 1,
            "skipped": 0,
            "status": "fail",
            "checks": [
                {"name": "Certificate verification", "category": "rust-proofs", "status": "pass", "elapsed_s": 5, "log": "certificate_verification.log"},
                {"name": "Lease semantics", "category": "integration-proofs", "status": "fail", "elapsed_s": 12, "log": "lease_semantics.log"}
            ]
        }"#,
    )
    .expect("valid JSON");

    let errors = validate_manifest(&manifest);
    assert!(errors.is_empty(), "unexpected validation errors: {:?}", errors);
}

#[test]
fn manifest_rejects_missing_fields() {
    let manifest: Value = serde_json::from_str(
        r#"{
            "version": "1.0.0",
            "total": 1,
            "passed": 1,
            "failed": 0,
            "skipped": 0,
            "status": "pass",
            "checks": []
        }"#,
    )
    .expect("valid JSON");

    let errors = validate_manifest(&manifest);
    assert!(!errors.is_empty(), "should have validation errors for missing fields");
    assert!(errors.iter().any(|e| e.contains("bead")));
    assert!(errors.iter().any(|e| e.contains("started_at")));
    assert!(errors.iter().any(|e| e.contains("git_sha")));
}

#[test]
fn manifest_rejects_bad_arithmetic() {
    let manifest: Value = serde_json::from_str(
        r#"{
            "version": "1.0.0",
            "bead": "bd-test",
            "started_at": "2026-02-04T06:00:00Z",
            "finished_at": "2026-02-04T06:05:00Z",
            "git_sha": "abc1234",
            "git_branch": "main",
            "total": 5,
            "passed": 2,
            "failed": 1,
            "skipped": 0,
            "status": "fail",
            "checks": []
        }"#,
    )
    .expect("valid JSON");

    let errors = validate_manifest(&manifest);
    assert!(errors.iter().any(|e| e.contains("total")), "should detect arithmetic mismatch: {:?}", errors);
}

#[test]
fn manifest_rejects_invalid_status() {
    let manifest: Value = serde_json::from_str(
        r#"{
            "version": "1.0.0",
            "bead": "bd-test",
            "started_at": "2026-02-04T06:00:00Z",
            "finished_at": "2026-02-04T06:05:00Z",
            "git_sha": "abc1234",
            "git_branch": "main",
            "total": 1,
            "passed": 1,
            "failed": 0,
            "skipped": 0,
            "status": "maybe",
            "checks": [
                {"name": "test", "category": "cat", "status": "unknown", "elapsed_s": 1, "log": "test.log"}
            ]
        }"#,
    )
    .expect("valid JSON");

    let errors = validate_manifest(&manifest);
    assert!(errors.iter().any(|e| e.contains("'status' must be")), "should reject invalid status values: {:?}", errors);
}

#[test]
fn manifest_rejects_bad_version() {
    let manifest: Value = serde_json::from_str(
        r#"{
            "version": "1.0",
            "bead": "bd-test",
            "started_at": "2026-02-04T06:00:00Z",
            "finished_at": "2026-02-04T06:05:00Z",
            "git_sha": "abc1234",
            "git_branch": "main",
            "total": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "status": "pass",
            "checks": []
        }"#,
    )
    .expect("valid JSON");

    let errors = validate_manifest(&manifest);
    assert!(errors.iter().any(|e| e.contains("semver")), "should reject non-semver version: {:?}", errors);
}

/// Validate TLA+ model check result format.
#[test]
fn tla_result_schema_valid() {
    let result_path = std::path::Path::new("formal/tla/output/result.json");
    if !result_path.exists() {
        eprintln!("TLA+ result not found at {}, skipping", result_path.display());
        return;
    }

    let content = std::fs::read_to_string(result_path).expect("read TLA+ result");
    let result: Value = serde_json::from_str(&content).expect("valid JSON");

    // Required fields
    assert!(result.get("status").is_some(), "missing 'status'");
    assert!(result.get("spec").is_some(), "missing 'spec'");
    assert!(result.get("bead").is_some(), "missing 'bead'");
    assert!(result.get("invariants_checked").is_some(), "missing 'invariants_checked'");

    let status = result["status"].as_str().unwrap();
    assert!(
        status == "pass" || status == "fail" || status == "skipped",
        "unexpected status: {status}"
    );

    if status == "pass" {
        assert!(result.get("violations").is_some(), "pass result should have 'violations'");
        let violations = result["violations"].as_u64().unwrap();
        assert_eq!(violations, 0, "pass result should have 0 violations");
    }
}
