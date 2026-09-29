//! Fail-closed contract for the dormant real-E2E inventory.
//!
//! Bead: asupersync-d24mms.12.1
//! Fixture: artifacts/dormant_e2e_inventory_v1.json

#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const ARTIFACT_PATH: &str = "artifacts/dormant_e2e_inventory_v1.json";
const DOC_PATH: &str = "docs/dormant_e2e_inventory.md";
const LIB_PATH: &str = "src/lib.rs";
const BEAD_ID: &str = "asupersync-d24mms.12.1";
const CAPABILITY_IDS: [&str; 2] = ["CAP-REAL-SERVICE-E2E", "CAP-VERIFICATION-PROFILES"];
const FORBIDDEN_MODULE_DECLARATIONS: [&str; 3] = [
    "mod real_fs_dir_fs_vfs_integration_e2e_tests;",
    "mod real_integration_scenarios_e2e_tests;",
    "mod real_distributed_e2e_tests;",
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn parse_inventory() -> Value {
    serde_json::from_str(&read_repo_file(ARTIFACT_PATH))
        .unwrap_or_else(|error| panic!("{ARTIFACT_PATH} must be valid JSON: {error}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn strings(value: &Value, key: &str) -> Vec<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_owned()
        })
        .collect()
}

fn sha256(path: &str) -> String {
    let bytes = std::fs::read(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"));
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn assert_nonempty_strings(row: &Value, key: &str, context: &str) {
    let values = array(row, key);
    assert!(!values.is_empty(), "{context}: {key} must not be empty");
    assert!(
        values
            .iter()
            .all(|value| value.as_str().is_some_and(|text| !text.trim().is_empty())),
        "{context}: {key} entries must be nonempty strings"
    );
}

fn assert_nonempty_string(row: &Value, key: &str, context: &str) {
    assert!(
        row.get(key)
            .and_then(Value::as_str)
            .is_some_and(|text| !text.trim().is_empty()),
        "{context}: {key} must be a nonempty string"
    );
}

fn structural_errors(inventory: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    let Some(rows) = inventory.get("test_inventory").and_then(Value::as_array) else {
        return vec!["test_inventory is missing".to_owned()];
    };
    if rows.len() != 27 {
        errors.push(format!("expected 27 inventory rows, found {}", rows.len()));
    }
    for (index, row) in rows.iter().enumerate() {
        if row
            .get("repair_owner")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            errors.push(format!("row {index} has no repair owner"));
        }
    }
    let Some(modules) = inventory.get("modules").and_then(Value::as_array) else {
        errors.push("modules is missing".to_owned());
        return errors;
    };
    for (index, module) in modules.iter().enumerate() {
        if module
            .pointer("/compile_probe/outcome")
            .and_then(Value::as_str)
            != Some("BLOCKED_COMPILE_DRIFT")
        {
            errors.push(format!("module {index} is not fail-closed"));
        }
    }
    errors
}

#[test]
fn inventory_pins_all_dormant_sources_and_compile_drift() {
    let inventory = parse_inventory();
    assert_eq!(structural_errors(&inventory), Vec::<String>::new());
    assert_eq!(string(&inventory, "bead_id"), BEAD_ID);
    assert_eq!(
        strings(&inventory, "capability_ids"),
        CAPABILITY_IDS.map(str::to_owned)
    );

    let modules = array(&inventory, "modules");
    assert_eq!(modules.len(), 3);
    let expected = BTreeMap::from([
        (
            "src/real_fs_dir_fs_vfs_integration_e2e_tests.rs",
            (
                "ffda7940ab83b3c7abbf41e8b9734759a35ebb315f36807d779e5163db4c9266",
                1223_u64,
                5_u64,
                8_u64,
                BTreeSet::from(["E0432", "E0599", "E0603"]),
            ),
        ),
        (
            "src/real_integration_scenarios_e2e_tests.rs",
            (
                "2caab9f01c37d1dff1698aec59b1aea4fce40db86ffa3094d231206cd7cb97de",
                5728,
                17,
                247,
                BTreeSet::from([
                    "E0061", "E0277", "E0308", "E0423", "E0425", "E0432", "E0532", "E0599", "E0608",
                ]),
            ),
        ),
        (
            "src/real_distributed_e2e_tests.rs",
            (
                "315a2c5ff591437348b3ec7f49c2b88de5bc3e6cefff1d3fdfc6d4c1aed243ae",
                828,
                5,
                23,
                BTreeSet::from(["E0061", "E0277", "E0599"]),
            ),
        ),
    ]);

    for module in modules {
        let path = string(module, "path");
        let &(hash, line_count, entrypoint_count, error_count, ref error_codes) = expected
            .get(path)
            .unwrap_or_else(|| panic!("unexpected module {path}"));
        assert_eq!(string(module, "sha256"), hash, "{path}: stale hash pin");
        assert_eq!(sha256(path), hash, "{path}: source changed after inventory");
        assert_eq!(
            std::fs::read_to_string(repo_root().join(path))
                .expect("inventoried source must be readable")
                .lines()
                .count() as u64,
            line_count,
            "{path}: stale line count"
        );
        assert_eq!(
            module.get("line_count").and_then(Value::as_u64),
            Some(line_count)
        );
        assert_eq!(
            module.get("entrypoint_count").and_then(Value::as_u64),
            Some(entrypoint_count)
        );
        assert_eq!(module.get("declared_in_lib"), Some(&Value::Bool(false)));
        assert_nonempty_strings(module, "logical_scenarios", path);
        assert_nonempty_strings(module, "fixtures", path);
        assert_nonempty_string(module, "cleanup_contract", path);

        let probe = module
            .get("compile_probe")
            .expect("compile_probe must be present");
        assert_eq!(string(probe, "outcome"), "BLOCKED_COMPILE_DRIFT");
        assert_eq!(probe.get("exit_code").and_then(Value::as_i64), Some(101));
        assert_eq!(
            probe.get("error_count").and_then(Value::as_u64),
            Some(error_count)
        );
        assert_eq!(
            strings(probe, "error_codes")
                .into_iter()
                .collect::<BTreeSet<_>>(),
            error_codes
                .iter()
                .map(|code| (*code).to_owned())
                .collect::<BTreeSet<_>>()
        );
        assert!(
            string(probe, "command").contains("RCH_REQUIRE_REMOTE=1 rch exec"),
            "{path}: compile probe must be remote-required"
        );
        assert_nonempty_strings(probe, "representative_diagnostics", path);
    }
}

#[test]
fn every_test_entrypoint_has_fail_closed_ownership_and_evidence() {
    let inventory = parse_inventory();
    let rows = array(&inventory, "test_inventory");
    assert_eq!(rows.len(), 27);

    let expected_counts = BTreeMap::from([
        (
            "src/real_fs_dir_fs_vfs_integration_e2e_tests.rs",
            (5_usize, "#[test]", "asupersync-d24mms.12.2"),
        ),
        (
            "src/real_integration_scenarios_e2e_tests.rs",
            (17, "#[tokio::test]", "asupersync-d24mms.12.3"),
        ),
        (
            "src/real_distributed_e2e_tests.rs",
            (5, "#[test]", "asupersync-d24mms.12.4"),
        ),
    ]);

    let mut ids = BTreeSet::new();
    let mut names_by_file: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut blocked = 0;
    let mut placeholders = 0;

    for row in rows {
        let id = string(row, "scenario_id");
        assert!(ids.insert(id), "duplicate scenario_id {id}");
        let source = string(row, "source_file");
        let test_function = string(row, "test_function");
        let &(_, _, owner) = expected_counts
            .get(source)
            .unwrap_or_else(|| panic!("{id}: unexpected source_file {source}"));
        assert_eq!(string(row, "repair_owner"), owner, "{id}: wrong owner");
        assert!(
            read_repo_file(source).contains(&format!("fn {test_function}")),
            "{id}: {test_function} is not present in {source}"
        );
        assert!(
            names_by_file
                .entry(source)
                .or_default()
                .insert(test_function),
            "{id}: duplicate test function inventory"
        );
        assert_nonempty_strings(row, "covers", id);
        assert_nonempty_strings(row, "expected_assertions", id);
        assert_nonempty_strings(row, "fixtures", id);
        assert_nonempty_strings(row, "cleanup", id);
        match string(row, "status") {
            "BLOCKED_REPAIR" => blocked += 1,
            "PLACEHOLDER_NOT_EVIDENCE" => {
                placeholders += 1;
                assert_eq!(string(row, "coverage"), "NO_COVERAGE");
                assert!(
                    array(row, "existing_evidence").is_empty(),
                    "{id}: placeholder cannot cite replacement evidence"
                );
            }
            status => panic!("{id}: non-fail-closed status {status}"),
        }
    }

    assert_eq!(blocked, 26);
    assert_eq!(placeholders, 1);
    for (source, (count, attribute, _)) in expected_counts {
        assert_eq!(
            names_by_file.get(source).map(BTreeSet::len),
            Some(count),
            "{source}: incomplete inventory"
        );
        assert_eq!(
            read_repo_file(source).matches(attribute).count(),
            count,
            "{source}: test attribute count drifted"
        );
    }
}

#[test]
fn dormant_state_policy_and_human_matrix_are_discoverable() {
    let inventory = parse_inventory();
    let lib = read_repo_file(LIB_PATH);
    for declaration in FORBIDDEN_MODULE_DECLARATIONS {
        assert!(
            !lib.contains(declaration),
            "{declaration} became active without downstream repair proof"
        );
    }

    let requirements = inventory
        .get("common_test_requirements")
        .expect("common_test_requirements must be present");
    assert_eq!(
        strings(requirements, "capability_ids"),
        CAPABILITY_IDS.map(str::to_owned)
    );
    assert_eq!(
        string(requirements, "runner_owner"),
        "asupersync-d24mms.12.5"
    );
    for invariant in [
        "no task leaks",
        "no obligation leaks",
        "race losers drained",
        "region close implies quiescence",
    ] {
        assert!(
            strings(requirements, "required_invariants")
                .iter()
                .any(|entry| entry == invariant),
            "missing invariant {invariant}"
        );
    }

    let summary = inventory.get("summary").expect("summary must be present");
    assert_eq!(
        summary.get("entrypoint_count").and_then(Value::as_u64),
        Some(27)
    );
    assert_eq!(
        summary
            .get("compiled_entrypoint_count")
            .and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        summary
            .get("deleted_or_ignored_count")
            .and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        summary.get("compile_error_count").and_then(Value::as_u64),
        Some(278)
    );
    assert_nonempty_strings(&inventory, "no_claim_boundaries", "inventory");

    let docs = read_repo_file(DOC_PATH);
    for marker in [
        "None of their tests currently",
        "Twenty-six",
        "`PLACEHOLDER_NOT_EVIDENCE`",
        "No dormant journey is",
        "no task leaks",
        "region-close quiescence",
    ] {
        assert!(docs.contains(marker), "docs missing marker {marker}");
    }
}

#[test]
fn malformed_inventory_fails_closed() {
    let inventory = parse_inventory();

    let mut missing_row = inventory.clone();
    missing_row
        .get_mut("test_inventory")
        .and_then(Value::as_array_mut)
        .expect("test_inventory must be mutable")
        .pop();
    assert!(
        structural_errors(&missing_row)
            .iter()
            .any(|error| error.contains("expected 27 inventory rows"))
    );

    let mut false_green = inventory.clone();
    false_green["modules"][0]["compile_probe"]["outcome"] = Value::String("COMPILED".into());
    assert!(
        structural_errors(&false_green)
            .iter()
            .any(|error| error.contains("not fail-closed"))
    );

    let mut missing_owner = inventory.clone();
    missing_owner["test_inventory"][0]["repair_owner"] = Value::String(String::new());
    assert!(
        structural_errors(&missing_owner)
            .iter()
            .any(|error| error.contains("no repair owner"))
    );
}

/// Top-level `src/*.rs` files that no module declaration, `#[path]` attribute or
/// `include!` reaches are never compiled. They cannot fail, so they prove nothing
/// (asupersync-bi2462.141). Ratchet: this number may only go down. When
/// orphans are wired in or archived, lower it in the same commit. Never raise it.
const MAX_TOP_LEVEL_SOURCE_ORPHANS: usize = 230;

/// Module names declared as `mod NAME;` (optionally `pub`/`pub(..)` and with
/// leading attributes on the same line) in a crate-root source file.
fn declared_file_modules(root_source: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for line in root_source.lines() {
        let mut rest = line.trim();
        if rest.starts_with("//") {
            continue;
        }
        while let Some(stripped) = rest.strip_prefix("#[") {
            let Some(end) = stripped.find(']') else { break };
            rest = stripped[end + 1..].trim_start();
        }
        if let Some(stripped) = rest.strip_prefix("pub") {
            rest = stripped.trim_start();
            if rest.starts_with('(') {
                let Some(end) = rest.find(')') else { continue };
                rest = rest[end + 1..].trim_start();
            }
        }
        let Some(stripped) = rest.strip_prefix("mod ") else {
            continue;
        };
        let name: String = stripped
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let after = stripped.trim_start()[name.len()..].trim_start();
        if !name.is_empty() && after.starts_with(';') {
            names.insert(name);
        }
    }
    names
}

/// Normalizes `a/b/../c` style relative paths without touching the filesystem.
fn normalize_relative(path: &std::path::Path) -> PathBuf {
    let mut parts: Vec<std::ffi::OsString> = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                parts.pop();
            }
            std::path::Component::CurDir => {}
            other => parts.push(other.as_os_str().to_owned()),
        }
    }
    parts.iter().collect()
}

/// Top-level `src/*.rs` file names reached through `#[path = "..."]` or
/// `include!("...rs")` from any Rust file under the given repository-relative
/// directories.
fn path_referenced_top_level_sources(dirs: &[&str]) -> BTreeSet<String> {
    fn walk(root: &std::path::Path, relative: &std::path::Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(root.join(relative)) else {
            return;
        };
        for entry in entries.flatten() {
            let rel = relative.join(entry.file_name());
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                walk(root, &rel, out);
            } else if rel.extension().is_some_and(|ext| ext == "rs") {
                out.push(rel);
            }
        }
    }
    let root = repo_root();
    let mut files = Vec::new();
    for dir in dirs {
        walk(&root, std::path::Path::new(dir), &mut files);
    }
    let mut referenced = BTreeSet::new();
    for file in files {
        let Ok(text) = std::fs::read_to_string(root.join(&file)) else {
            continue;
        };
        let base = file.parent().unwrap_or_else(|| std::path::Path::new(""));
        let mut targets = Vec::new();
        for (marker, terminator) in [("#[path = \"", '"'), ("include!(\"", '"')] {
            let mut cursor = text.as_str();
            while let Some(start) = cursor.find(marker) {
                let tail = &cursor[start + marker.len()..];
                if let Some(end) = tail.find(terminator) {
                    targets.push(tail[..end].to_owned());
                }
                cursor = tail;
            }
        }
        for target in targets {
            let resolved = normalize_relative(&base.join(&target));
            let mut components = resolved.components();
            if let (Some(first), Some(second), None) =
                (components.next(), components.next(), components.next())
            {
                if first.as_os_str() == "src" {
                    referenced.insert(second.as_os_str().to_string_lossy().into_owned());
                }
            }
        }
    }
    referenced
}

fn top_level_source_orphans() -> BTreeSet<String> {
    let declared = declared_file_modules(&read_repo_file(LIB_PATH));
    let referenced = path_referenced_top_level_sources(&["src", "tests", "benches", "examples"]);
    let entries = std::fs::read_dir(repo_root().join("src")).expect("src/ must be readable");
    let mut orphans = BTreeSet::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_file = entry.file_type().is_ok_and(|kind| kind.is_file());
        let Some(stem) = name.strip_suffix(".rs") else {
            continue;
        };
        if !is_file || name == "lib.rs" || name == "main.rs" {
            continue;
        }
        if declared.contains(stem) || referenced.contains(&name) {
            continue;
        }
        orphans.insert(name);
    }
    orphans
}

#[test]
fn source_orphan_census_parser_fails_closed_on_planted_cases() {
    let planted = "pub mod live_a;\n#[cfg(feature = \"x\")] pub(crate) mod live_b;\n\
                   // mod commented_out;\nmod inline_block { }\nmod live_c ;\n";
    let declared = declared_file_modules(planted);
    assert_eq!(
        declared,
        ["live_a", "live_b", "live_c"]
            .into_iter()
            .map(String::from)
            .collect::<BTreeSet<_>>(),
        "only `mod NAME;` declarations count as file modules"
    );
    assert_eq!(
        normalize_relative(std::path::Path::new("src/util/../future.rs")),
        PathBuf::from("src/future.rs")
    );
}

#[test]
fn top_level_source_orphans_never_increase() {
    let orphans = top_level_source_orphans();
    eprintln!(
        "top-level source orphans: {} (ratchet max {MAX_TOP_LEVEL_SOURCE_ORPHANS})",
        orphans.len()
    );
    assert!(
        orphans.len() <= MAX_TOP_LEVEL_SOURCE_ORPHANS,
        "{} top-level src/*.rs files are never compiled (ratchet max {MAX_TOP_LEVEL_SOURCE_ORPHANS}). \
         A new source file must be declared in src/lib.rs or reached by #[path]/include!, or it \
         proves nothing. Orphans: {orphans:?}",
        orphans.len()
    );
    // A known orphan must be detected, so the census cannot silently pass by
    // failing to see anything (asupersync-bi2462.141).
    assert!(
        orphans.contains("real_distributed_e2e_tests.rs"),
        "census must detect the pinned dormant module; found {orphans:?}"
    );
}

/// Nested `src/**/*.rs` files (below the top level of `src/`) that nothing compiles.
/// No crate root reaches them through column-0 `mod NAME;` declarations (honouring
/// `#[path]`) or `include!`, and no `#[path]`/`include!` in tests/, benches/ or
/// examples/ names them. The top-level census above cannot see this class:
/// `src/lab/runtime/production_strict.rs`, a finished module nothing declared, hid in
/// it until asupersync-bi2462.96. Ratchet: this number may only go down
/// (asupersync-bi2462.141). When nested orphans are wired in or archived, lower it in
/// the same commit. Never raise it.
const MAX_NESTED_SOURCE_ORPHANS: usize = 65;

/// Repository-relative, `/`-separated `.rs` files under `dir`.
fn rust_files_under(dir: &str) -> Vec<String> {
    fn walk(root: &std::path::Path, relative: &str, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(root.join(relative)) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = format!("{relative}/{name}");
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                walk(root, &rel, out);
            } else if std::path::Path::new(&name)
                .extension()
                .is_some_and(|ext| ext == "rs")
            {
                out.push(rel);
            }
        }
    }
    let mut out = Vec::new();
    walk(&repo_root(), dir, &mut out);
    out.sort();
    out
}

/// `base/target`, normalized and `/`-separated.
fn join_relative(base: &str, target: &str) -> String {
    normalize_relative(&std::path::Path::new(base).join(target))
        .to_string_lossy()
        .replace('\\', "/")
}

/// The quoted argument following every occurrence of `marker` in `text`.
fn quoted_after(text: &str, marker: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut cursor = text;
    while let Some(start) = cursor.find(marker) {
        let tail = &cursor[start + marker.len()..];
        if let Some(end) = tail.find('"') {
            found.push(tail[..end].to_owned());
        }
        cursor = tail;
    }
    found
}

fn bracket_balance(line: &str) -> i32 {
    let opened = line.matches('[').count();
    let closed = line.matches(']').count();
    i32::try_from(opened).unwrap_or(i32::MAX) - i32::try_from(closed).unwrap_or(i32::MAX)
}

/// Files reached from `roots` (path, whether it resolves children like a `mod.rs`), as
/// rustc resolves them: column-0 `mod NAME;` declarations, a `#[path]` among the
/// attributes stacked above one, and `include!`. An indented declaration (inside an
/// inline module) is not followed, so its file counts as unreached: the census then
/// fails loudly rather than passing blind.
fn reachable_sources(
    roots: &[(String, bool)],
    sources: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    let mut reached = BTreeSet::new();
    let mut stack = roots.to_vec();
    while let Some((path, mod_rs)) = stack.pop() {
        let Some(text) = sources.get(&path) else {
            continue;
        };
        if !reached.insert(path.clone()) {
            continue;
        }
        let dir = path.rsplit_once('/').map_or("", |(dir, _)| dir).to_owned();
        let child_dir = if mod_rs {
            dir.clone()
        } else {
            path.trim_end_matches(".rs").to_owned()
        };
        let mut explicit_path: Option<String> = None;
        let mut attr_depth = 0;
        for line in text.lines() {
            let trimmed = line.trim();
            if attr_depth > 0 {
                attr_depth += bracket_balance(trimmed);
                continue;
            }
            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }
            if trimmed.starts_with("#[") {
                if let Some(value) = quoted_after(trimmed, "#[path = \"").into_iter().next() {
                    explicit_path = Some(value);
                }
                attr_depth = bracket_balance(trimmed);
                if attr_depth > 0 {
                    continue;
                }
            }
            let column_zero = !line.starts_with(char::is_whitespace);
            let declared = if column_zero {
                declared_file_modules(line)
            } else {
                BTreeSet::new()
            };
            if let Some(name) = declared.into_iter().next() {
                let child = explicit_path.take().map_or_else(
                    || {
                        let flat = format!("{child_dir}/{name}.rs");
                        if sources.contains_key(&flat) {
                            (flat, false)
                        } else {
                            (format!("{child_dir}/{name}/mod.rs"), true)
                        }
                    },
                    |target| (join_relative(&dir, &target), true),
                );
                stack.push(child);
            } else if !trimmed.starts_with("#[") {
                explicit_path = None;
            }
        }
        for target in quoted_after(text, "include!(\"") {
            stack.push((join_relative(&dir, &target), mod_rs));
        }
    }
    reached
}

fn nested_source_orphans() -> BTreeSet<String> {
    let root = repo_root();
    let sources: BTreeMap<String, String> = rust_files_under("src")
        .into_iter()
        .filter_map(|path| {
            let text = std::fs::read_to_string(root.join(&path)).ok()?;
            Some((path, text))
        })
        .collect();
    let mut roots = vec![(LIB_PATH.to_owned(), true)];
    for path in sources.keys() {
        let bin = path.strip_prefix("src/bin/");
        let auto_bin = bin.is_some_and(|rest| {
            !rest.contains('/') || (rest.ends_with("/main.rs") && rest.matches('/').count() == 1)
        });
        if path == "src/main.rs" || auto_bin {
            roots.push((path.clone(), true));
        }
    }
    for target in quoted_after(&read_repo_file("Cargo.toml"), "path = \"src/") {
        roots.push((format!("src/{target}"), true));
    }
    for dir in ["tests", "benches", "examples"] {
        for file in rust_files_under(dir) {
            let Ok(text) = std::fs::read_to_string(root.join(&file)) else {
                continue;
            };
            let base = file.rsplit_once('/').map_or("", |(base, _)| base);
            for target in quoted_after(&text, "#[path = \"")
                .into_iter()
                .chain(quoted_after(&text, "include!(\""))
            {
                let resolved = join_relative(base, &target);
                if resolved.starts_with("src/") {
                    roots.push((resolved, true));
                }
            }
        }
    }
    let reached = reachable_sources(&roots, &sources);
    sources
        .keys()
        .filter(|path| path.matches('/').count() > 1 && !reached.contains(*path))
        .cloned()
        .collect()
}

#[test]
fn nested_orphan_walk_follows_path_and_include_on_planted_tree() {
    let planted: BTreeMap<String, String> = [
        (
            "src/lib.rs",
            "pub mod plain;\n#[cfg(all(\n    unix,\n    feature = \"x\"\n))]\n\
             #[path = \"io_backend.rs\"]\npub mod backend;\n\
             #[cfg(test)] #[path = \"lib_tests.rs\"] mod lib_tests;\n\
             pub mod nested;\n// mod commented;\nmod inline {\n    mod indented;\n}\n",
        ),
        (
            "src/plain.rs",
            "mod child;\ninclude!(\"plain_tests.rs\");\n",
        ),
        ("src/plain/child.rs", ""),
        ("src/plain_tests.rs", ""),
        ("src/io_backend.rs", ""),
        // Shadowed by the #[path] above: nothing compiles it.
        ("src/backend.rs", ""),
        ("src/lib_tests.rs", ""),
        ("src/nested/mod.rs", "pub mod leaf;\n"),
        ("src/nested/leaf.rs", ""),
        ("src/nested/stale.rs", ""),
        ("src/commented.rs", ""),
        ("src/inline/indented.rs", ""),
    ]
    .into_iter()
    .map(|(path, text)| (path.to_owned(), text.to_owned()))
    .collect();
    let reached = reachable_sources(&[("src/lib.rs".to_owned(), true)], &planted);
    let expected: BTreeSet<String> = [
        "src/io_backend.rs",
        "src/lib.rs",
        "src/lib_tests.rs",
        "src/nested/leaf.rs",
        "src/nested/mod.rs",
        "src/plain.rs",
        "src/plain/child.rs",
        "src/plain_tests.rs",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(reached, expected);
}

#[test]
fn nested_source_orphans_never_increase() {
    let orphans = nested_source_orphans();
    eprintln!(
        "nested source orphans: {} (ratchet max {MAX_NESTED_SOURCE_ORPHANS})",
        orphans.len()
    );
    assert!(
        orphans.len() <= MAX_NESTED_SOURCE_ORPHANS,
        "{} nested src/**/*.rs files are never compiled (ratchet max {MAX_NESTED_SOURCE_ORPHANS}). \
         A new source file must be declared by its parent module or reached by #[path]/include!, \
         or it proves nothing. Orphans: {orphans:?}",
        orphans.len()
    );
    // The census must see a pinned nested orphan (the superseded net::quic tree) and must
    // not flag files reached only through #[path] or include!.
    assert!(
        orphans.contains("src/net/quic/connection.rs"),
        "census must detect the pinned nested orphan; found {orphans:?}"
    );
    for reached in [
        "src/runtime/reactor/io_uring.rs",
        "src/database/postgres_tests.rs",
        "src/lab/runtime/production_strict.rs",
    ] {
        assert!(
            !orphans.contains(reached),
            "{reached} is compiled (#[path], include! or a plain declaration) but was counted as an orphan"
        );
    }
}
