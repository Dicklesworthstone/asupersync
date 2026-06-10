use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const REGISTRY: &str = "docs/error_codes/registry.json";
const ERROR_CODES_README: &str = "docs/error_codes/README.md";
const README: &str = "README.md";
const AGENTS: &str = "AGENTS.md";

fn repo_path(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn read(path: &str) -> String {
    fs::read_to_string(repo_path(path)).unwrap_or_else(|err| panic!("failed to read {path}: {err}"))
}

fn as_array<'a>(entry: &'a Value, field: &str) -> &'a Vec<Value> {
    entry[field]
        .as_array()
        .unwrap_or_else(|| panic!("{field} must be an array in {entry}"))
}

fn as_str<'a>(entry: &'a Value, field: &str) -> &'a str {
    entry[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} must be a string in {entry}"))
}

fn is_error_code(code: &str) -> bool {
    let bytes = code.as_bytes();
    bytes.len() == 9
        && code.starts_with("ASUP-E")
        && bytes[6].is_ascii_digit()
        && bytes[7].is_ascii_digit()
        && bytes[8].is_ascii_digit()
}

fn extract_asup_codes(text: &str) -> BTreeSet<String> {
    let mut codes = BTreeSet::new();
    let mut offset = 0;

    while let Some(found) = text[offset..].find("ASUP-E") {
        let start = offset + found;
        let end = start + 9;
        if end <= text.len() {
            let candidate = &text[start..end];
            if is_error_code(candidate) {
                codes.insert(candidate.to_string());
            }
        }
        offset = start + "ASUP-E".len();
    }

    codes
}

fn rust_source_files(root: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).unwrap_or_else(|err| panic!("failed to read {root:?}: {err}")) {
        let entry = entry.expect("directory entry should be readable");
        let path = entry.path();
        if path.is_dir() {
            rust_source_files(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

fn src_asup_codes() -> BTreeSet<String> {
    let mut paths = Vec::new();
    rust_source_files(&repo_path("src"), &mut paths);

    let mut codes = BTreeSet::new();
    for path in paths {
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read source file {path:?}: {err}"));
        codes.extend(extract_asup_codes(&text));
    }
    codes
}

fn readme_catalog_statuses() -> BTreeMap<String, String> {
    let readme = read(ERROR_CODES_README);
    let mut statuses = BTreeMap::new();
    let mut in_catalog = false;

    for line in readme.lines() {
        let trimmed = line.trim();
        if trimmed == "| Code | Status | Area | Page |" {
            in_catalog = true;
            continue;
        }

        if !in_catalog {
            continue;
        }

        if trimmed.starts_with("|------") {
            continue;
        }

        if !trimmed.starts_with('|') {
            break;
        }

        let cells: Vec<_> = trimmed
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        assert_eq!(cells.len(), 4, "catalog row must have four columns: {line}");

        let code = cells[0];
        assert!(is_error_code(code), "catalog row has invalid code: {line}");
        assert!(
            matches!(cells[1], "live" | "reserved"),
            "catalog row has invalid status: {line}"
        );

        let prior = statuses.insert(code.to_string(), cells[1].to_string());
        assert!(prior.is_none(), "duplicate README catalog row for {code}");
    }

    assert!(!statuses.is_empty(), "README error-code catalog not found");
    statuses
}

#[test]
fn error_code_registry_schema_and_pages_are_complete() {
    let registry: Value = serde_json::from_str(&read(REGISTRY)).expect("registry must be JSON");
    assert_eq!(
        registry["schema_version"],
        "asupersync-error-code-registry-v1"
    );

    let codes = registry["codes"]
        .as_array()
        .expect("registry codes must be an array");
    assert!(
        codes.len() >= 25,
        "registry must seed at least 25 first-day codes"
    );

    let mut seen = BTreeSet::new();
    for entry in codes {
        let code = as_str(entry, "code");
        assert!(is_error_code(code), "invalid ASUP code: {code}");
        assert!(seen.insert(code), "duplicate registry code {code}");

        for field in ["name", "area", "status", "summary", "doc_path", "since"] {
            assert!(
                !as_str(entry, field).trim().is_empty(),
                "{code} missing {field}"
            );
        }
        assert!(
            matches!(as_str(entry, "status"), "live" | "reserved"),
            "{code} has invalid status"
        );
        assert!(
            !as_array(entry, "probable_causes").is_empty(),
            "{code} must include probable causes"
        );
        assert!(
            !as_array(entry, "remediation").is_empty(),
            "{code} must include remediation steps"
        );

        let doc_path = as_str(entry, "doc_path");
        assert!(
            doc_path.starts_with("docs/error_codes/"),
            "{code} doc path must stay under docs/error_codes"
        );
        let page = read(doc_path);
        for required in [
            code,
            "## Symptom",
            "## Probable Causes",
            "## Fix",
            "## Example",
            "## Related",
        ] {
            assert!(
                page.contains(required),
                "{doc_path} missing required template text {required}"
            );
        }
    }
}

#[test]
fn error_code_readme_catalog_matches_registry_statuses() {
    let registry: Value = serde_json::from_str(&read(REGISTRY)).expect("registry must be JSON");
    let registry_statuses: BTreeMap<_, _> = registry["codes"]
        .as_array()
        .expect("registry codes must be an array")
        .iter()
        .map(|entry| {
            (
                as_str(entry, "code").to_string(),
                as_str(entry, "status").to_string(),
            )
        })
        .collect();

    let readme_statuses = readme_catalog_statuses();
    assert_eq!(
        readme_statuses, registry_statuses,
        "docs/error_codes/README.md first-day catalog must mirror registry.json statuses"
    );
}

#[test]
fn live_error_codes_are_bidirectionally_linked_to_source() {
    let registry: Value = serde_json::from_str(&read(REGISTRY)).expect("registry must be JSON");
    let mut by_code = BTreeMap::new();
    for entry in registry["codes"]
        .as_array()
        .expect("registry codes must be an array")
    {
        by_code.insert(as_str(entry, "code").to_string(), entry);
    }

    let source_codes = src_asup_codes();
    assert!(
        !source_codes.is_empty(),
        "source should contain at least the live spawn ASUP codes"
    );

    for code in &source_codes {
        let entry = by_code
            .get(code)
            .unwrap_or_else(|| panic!("source references {code}, missing from registry"));
        assert_eq!(
            as_str(entry, "status"),
            "live",
            "source-referenced {code} must be marked live"
        );
    }

    for (code, entry) in by_code {
        if as_str(entry, "status") != "live" {
            continue;
        }
        let refs = as_array(entry, "source_refs");
        assert!(!refs.is_empty(), "live {code} must list source refs");
        let mut found_in_refs = false;
        for source_ref in refs {
            let path = source_ref
                .as_str()
                .unwrap_or_else(|| panic!("{code} source ref must be a string"));
            let text = read(path);
            found_in_refs |= text.contains(&code);
        }
        assert!(found_in_refs, "live {code} not found in listed source refs");
    }
}

#[test]
fn error_code_registry_is_discoverable_from_agent_docs() {
    let readme = read(README);
    let agents = read(AGENTS);
    assert!(readme.contains(REGISTRY), "README must link {REGISTRY}");
    assert!(agents.contains(REGISTRY), "AGENTS.md must link {REGISTRY}");
}
