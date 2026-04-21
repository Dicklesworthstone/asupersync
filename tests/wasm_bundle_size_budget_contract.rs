#![allow(warnings)]
#![allow(clippy::all)]
//! Contract tests for bundle-size budgets and regression gates (asupersync-3qv04.6.7.1).
//!
//! Validates that per-package and per-artifact size budgets are defined,
//! internally consistent, and enforced against actual artifacts when present.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_budget() -> serde_json::Value {
    let path = repo_root().join("artifacts/wasm_bundle_size_budget_v1.json");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    serde_json::from_str(&content).expect("invalid budget JSON")
}

fn read_pkg(pkg: &str) -> serde_json::Value {
    let path = repo_root().join("packages").join(pkg).join("package.json");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    serde_json::from_str(&content).expect("invalid package JSON")
}

const PACKAGES: &[(&str, &str)] = &[
    ("@asupersync/browser-core", "browser-core"),
    ("@asupersync/browser", "browser"),
    ("@asupersync/react", "react"),
    ("@asupersync/next", "next"),
];

// ── Artifact Presence ────────────────────────────────────────────────

#[test]
fn budget_artifact_exists_and_is_valid_json() {
    let budget = read_budget();
    assert!(
        budget["schema_version"].as_str().is_some(),
        "budget must have schema_version"
    );
    assert!(
        budget["packages"].is_object(),
        "budget must have packages object"
    );
}

#[test]
fn budget_covers_all_four_packages() {
    let budget = read_budget();
    let packages = budget["packages"].as_object().unwrap();
    for (scope_name, _) in PACKAGES {
        assert!(
            packages.contains_key(*scope_name),
            "budget missing package {scope_name}"
        );
    }
}

#[test]
fn budget_doc_exists() {
    let path = repo_root().join("docs/wasm_bundle_size_budget.md");
    assert!(path.exists(), "bundle size budget doc must exist");
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(
        content.contains("Hard Ceiling"),
        "doc must define hard ceilings"
    );
    assert!(
        content.contains("Warning"),
        "doc must define warning thresholds"
    );
}

// ── Budget Structure Validation ──────────────────────────────────────

#[test]
fn browser_core_has_per_artifact_budgets() {
    let budget = read_budget();
    let bc = &budget["packages"]["@asupersync/browser-core"];
    let artifacts = bc["artifacts"]
        .as_object()
        .expect("browser-core must have artifacts");

    let required = ["asupersync_bg.wasm", "index.js", "asupersync.js"];
    for name in &required {
        assert!(
            artifacts.contains_key(*name),
            "browser-core missing budget for {name}"
        );
        let entry = &artifacts[*name];
        assert!(
            entry["warning_bytes"].as_u64().unwrap() > 0,
            "{name} warning_bytes must be positive"
        );
        assert!(
            entry["ceiling_bytes"].as_u64().unwrap() > 0,
            "{name} ceiling_bytes must be positive"
        );
    }
}

#[test]
fn warning_is_less_than_ceiling_for_all_artifacts() {
    let budget = read_budget();
    let bc = &budget["packages"]["@asupersync/browser-core"];
    if let Some(artifacts) = bc["artifacts"].as_object() {
        for (name, entry) in artifacts {
            let warn = entry["warning_bytes"].as_u64().unwrap();
            let ceil = entry["ceiling_bytes"].as_u64().unwrap();
            assert!(
                warn < ceil,
                "{name}: warning ({warn}) must be less than ceiling ({ceil})"
            );
        }
    }

    let total_warn = bc["total_publishable"]["warning_bytes"].as_u64().unwrap();
    let total_ceil = bc["total_publishable"]["ceiling_bytes"].as_u64().unwrap();
    assert!(
        total_warn < total_ceil,
        "browser-core total: warning ({total_warn}) must be < ceiling ({total_ceil})"
    );
}

#[test]
fn higher_level_packages_have_dist_budgets() {
    let budget = read_budget();
    for (scope_name, _) in &PACKAGES[1..] {
        let pkg = &budget["packages"][*scope_name];
        let dist_warn = pkg["dist_total"]["warning_bytes"].as_u64();
        let dist_ceil = pkg["dist_total"]["ceiling_bytes"].as_u64();
        assert!(
            dist_warn.is_some() && dist_ceil.is_some(),
            "{scope_name} must have dist_total budget"
        );
        assert!(
            dist_warn.unwrap() < dist_ceil.unwrap(),
            "{scope_name} dist warning must be < ceiling"
        );
    }
}

#[test]
fn higher_level_packages_have_types_budgets() {
    let budget = read_budget();
    for (scope_name, _) in &PACKAGES[1..] {
        let pkg = &budget["packages"][*scope_name];
        let types_warn = pkg["dist_types_total"]["warning_bytes"].as_u64();
        let types_ceil = pkg["dist_types_total"]["ceiling_bytes"].as_u64();
        assert!(
            types_warn.is_some() && types_ceil.is_some(),
            "{scope_name} must have dist_types_total budget"
        );
        assert!(
            types_warn.unwrap() < types_ceil.unwrap(),
            "{scope_name} types warning must be < ceiling"
        );
    }
}

// ── Gzip Ceiling Consistency ─────────────────────────────────────────

#[test]
fn gzip_ceilings_are_within_ratio_of_raw_ceilings() {
    let budget = read_budget();
    let ratio = budget["gzip_ceiling_ratio"]
        .as_f64()
        .expect("gzip_ceiling_ratio must exist");
    assert!(
        (0.3..=0.8).contains(&ratio),
        "gzip ratio {ratio} must be between 0.3 and 0.8"
    );

    let bc = &budget["packages"]["@asupersync/browser-core"];
    if let Some(artifacts) = bc["artifacts"].as_object() {
        for (name, entry) in artifacts {
            if let Some(gzip_ceil) = entry["gzip_ceiling_bytes"].as_u64() {
                let raw_ceil = entry["ceiling_bytes"].as_u64().unwrap();
                #[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
                let expected_max = (raw_ceil as f64 * ratio).ceil() as u64;
                assert!(
                    gzip_ceil <= expected_max + 1,
                    "{name}: gzip ceiling ({gzip_ceil}) exceeds {ratio} * raw ceiling ({raw_ceil}) = {expected_max}"
                );
            }
        }
    }
}

// ── Profile Enforcement Policy ───────────────────────────────────────

#[test]
fn release_profile_is_enforced() {
    let budget = read_budget();
    let release = &budget["profiles"]["release"];
    assert_eq!(
        release["enforced"], true,
        "release profile must be enforced"
    );
}

#[test]
fn dev_and_profiling_profiles_are_not_enforced() {
    let budget = read_budget();
    assert_eq!(
        budget["profiles"]["dev"]["enforced"], false,
        "dev profile must not be enforced"
    );
    assert_eq!(
        budget["profiles"]["profiling"]["enforced"], false,
        "profiling profile must not be enforced"
    );
}

// ── Source Map Exclusion ─────────────────────────────────────────────

#[test]
fn source_maps_excluded_from_totals() {
    let budget = read_budget();
    let excluded = budget["excluded_from_totals"]
        .as_array()
        .expect("excluded_from_totals must be array");
    let patterns: Vec<&str> = excluded.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        patterns.iter().any(|p| p.contains(".js.map")),
        "must exclude JS source maps"
    );
    assert!(
        patterns.iter().any(|p| p.contains(".wasm.map")),
        "must exclude WASM source maps"
    );
}

// ── Delta Review Threshold ───────────────────────────────────────────

#[test]
fn delta_review_threshold_is_reasonable() {
    let budget = read_budget();
    let delta = budget["delta_review_threshold_ratio"]
        .as_f64()
        .expect("delta_review_threshold_ratio must exist");
    assert!(
        (0.01..=0.25).contains(&delta),
        "delta review threshold {delta} must be between 1% and 25%"
    );
}

// ── Band Definitions ─────────────────────────────────────────────────

#[test]
fn all_three_bands_defined() {
    let budget = read_budget();
    let bands = budget["bands"].as_object().expect("bands must be object");
    for band in ["green", "yellow", "red"] {
        assert!(bands.contains_key(band), "missing band definition: {band}");
    }
}

#[test]
fn red_band_mentions_ci_failure() {
    let budget = read_budget();
    let red = budget["bands"]["red"].as_str().unwrap().to_lowercase();
    assert!(
        red.contains("fail"),
        "red band must mention CI failure requirement"
    );
}

// ── Package Directory Consistency ────────────────────────────────────

#[test]
fn budget_directories_match_actual_packages() {
    let budget = read_budget();
    let packages = budget["packages"].as_object().unwrap();
    for (scope_name, dir) in PACKAGES {
        let budget_dir = packages[*scope_name]["directory"]
            .as_str()
            .unwrap_or_else(|| panic!("{scope_name} missing directory"));
        assert_eq!(
            budget_dir,
            format!("packages/{dir}"),
            "{scope_name} directory mismatch"
        );
        let actual_path = repo_root().join(budget_dir);
        assert!(
            actual_path.exists(),
            "{scope_name} directory {budget_dir} does not exist on disk"
        );
    }
}

// ── Artifact Size Validation (when built) ────────────────────────────

#[test]
fn browser_core_existing_artifacts_within_budget() {
    let budget = read_budget();
    let bc = &budget["packages"]["@asupersync/browser-core"];
    let artifacts = bc["artifacts"].as_object().unwrap();
    let pkg_dir = repo_root().join("packages/browser-core");

    let mut checked = 0u32;
    for (name, entry) in artifacts {
        let path = pkg_dir.join(name);
        if !path.exists() {
            continue;
        }
        checked += 1;
        let size = std::fs::metadata(&path).unwrap().len();
        let ceiling = entry["ceiling_bytes"].as_u64().unwrap();
        assert!(
            size <= ceiling,
            "{name}: actual size ({size} bytes) exceeds ceiling ({ceiling} bytes)"
        );

        let warning = entry["warning_bytes"].as_u64().unwrap();
        if size > warning {
            eprintln!(
                "ADVISORY: {name} ({size} bytes) exceeds warning threshold ({warning} bytes)"
            );
        }
    }
    if pkg_dir.join("index.js").exists() {
        assert!(checked >= 1, "expected at least one artifact to be checked");
    }
}

#[test]
fn browser_core_total_publishable_within_budget() {
    let budget = read_budget();
    let bc = &budget["packages"]["@asupersync/browser-core"];
    let pkg_dir = repo_root().join("packages/browser-core");

    let pkg = read_pkg("browser-core");
    let files: Vec<&str> = pkg["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f.as_str())
        .collect();

    let excluded: Vec<&str> = budget["excluded_from_totals"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();

    let mut total: u64 = 0;
    let mut found_any = false;
    for file in &files {
        if excluded.iter().any(|pat| {
            let suffix = pat.trim_start_matches('*');
            file.ends_with(suffix)
        }) {
            continue;
        }
        let path = pkg_dir.join(file);
        if path.exists() {
            found_any = true;
            total += std::fs::metadata(&path).unwrap().len();
        }
    }

    if found_any {
        let ceiling = bc["total_publishable"]["ceiling_bytes"].as_u64().unwrap();
        assert!(
            total <= ceiling,
            "browser-core total publishable ({total} bytes) exceeds ceiling ({ceiling} bytes)"
        );
    }
}

// ── Files Array Completeness ─────────────────────────────────────────

#[test]
fn browser_core_budgeted_artifacts_are_in_files_array() {
    let budget = read_budget();
    let bc = &budget["packages"]["@asupersync/browser-core"];
    let artifacts = bc["artifacts"].as_object().unwrap();

    let pkg = read_pkg("browser-core");
    let files: Vec<&str> = pkg["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f.as_str())
        .collect();

    for artifact_name in artifacts.keys() {
        assert!(
            files.contains(&artifact_name.as_str()),
            "budgeted artifact {artifact_name} not listed in browser-core files array"
        );
    }
}

// ── Budget Artifact Categories ───────────────────────────────────────

#[test]
fn all_browser_core_artifacts_have_categories() {
    let budget = read_budget();
    let bc = &budget["packages"]["@asupersync/browser-core"];
    let artifacts = bc["artifacts"].as_object().unwrap();
    let valid_categories = [
        "wasm_binary",
        "wasm_bindgen_glue",
        "js_facade",
        "type_declarations",
    ];

    for (name, entry) in artifacts {
        let cat = entry["category"]
            .as_str()
            .unwrap_or_else(|| panic!("{name} missing category"));
        assert!(
            valid_categories.contains(&cat),
            "{name} has unknown category {cat}"
        );
    }
}

// ── Cross-Reference: Budget Aligns with Existing Size Constraints ────

#[test]
fn wasm_binary_budget_is_under_one_megabyte() {
    let budget = read_budget();
    let wasm_ceil = budget["packages"]["@asupersync/browser-core"]["artifacts"]
        ["asupersync_bg.wasm"]["ceiling_bytes"]
        .as_u64()
        .unwrap();
    assert!(
        wasm_ceil <= 1_048_576,
        "WASM binary ceiling ({wasm_ceil}) should be <= 1 MB for reasonable browser load times"
    );
}

#[test]
fn js_facade_budget_is_under_64kb() {
    let budget = read_budget();
    let js_ceil =
        budget["packages"]["@asupersync/browser-core"]["artifacts"]["index.js"]["ceiling_bytes"]
            .as_u64()
            .unwrap();
    assert!(
        js_ceil <= 65536,
        "JS facade ceiling ({js_ceil}) should be <= 64 KB"
    );
}

#[test]
fn higher_level_dist_budgets_smaller_than_browser_core() {
    let budget = read_budget();
    let bc_total =
        budget["packages"]["@asupersync/browser-core"]["total_publishable"]["ceiling_bytes"]
            .as_u64()
            .unwrap();

    for (scope_name, _) in &PACKAGES[1..] {
        let dist_ceil = budget["packages"][*scope_name]["dist_total"]["ceiling_bytes"]
            .as_u64()
            .unwrap();
        assert!(
            dist_ceil < bc_total,
            "{scope_name} dist ceiling ({dist_ceil}) should be less than browser-core total ({bc_total})"
        );
    }
}

// ── Schema Version ───────────────────────────────────────────────────

#[test]
fn schema_version_is_semver() {
    let budget = read_budget();
    let version = budget["schema_version"].as_str().unwrap();
    let parts: Vec<&str> = version.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "schema_version must be semver (got {version})"
    );
    for (i, label) in ["major", "minor", "patch"].iter().enumerate() {
        assert!(
            parts[i].parse::<u32>().is_ok(),
            "schema_version {label} component is not numeric"
        );
    }
}

// ── Measurement Unit ─────────────────────────────────────────────────

#[test]
fn measurement_unit_is_bytes() {
    let budget = read_budget();
    assert_eq!(
        budget["measurement_unit"].as_str(),
        Some("bytes"),
        "measurement_unit must be 'bytes' for unambiguous comparison"
    );
}
