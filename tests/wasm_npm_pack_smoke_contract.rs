//! Contract tests for npm pack/install smoke validation (asupersync-3qv04.6.4).
//!
//! Validates that all four packages are pack-ready from a downstream consumer's
//! perspective: manifest integrity, exports resolution, dependency correctness,
//! artifact file references, and installability assumptions.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_pkg(pkg: &str) -> serde_json::Value {
    let path = repo_root().join("packages").join(pkg).join("package.json");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    serde_json::from_str(&content).expect("invalid JSON")
}

const ALL_PKGS: &[&str] = &["browser-core", "browser", "react", "next"];

// ── Pack-Ready Manifest Fields ───────────────────────────────────────

#[test]
fn all_packages_have_pack_required_fields() {
    let required_fields = [
        "name", "version", "type", "main", "types", "exports", "files",
    ];

    for pkg in ALL_PKGS {
        let v = read_pkg(pkg);
        for field in &required_fields {
            assert!(
                !v[field].is_null(),
                "{pkg} missing pack-required field: {field}"
            );
        }
    }
}

#[test]
fn all_packages_have_repository_and_homepage() {
    for pkg in ALL_PKGS {
        let v = read_pkg(pkg);
        assert!(
            v["repository"]["url"].as_str().is_some(),
            "{pkg} missing repository.url"
        );
        assert!(v["homepage"].as_str().is_some(), "{pkg} missing homepage");
    }
}

#[test]
fn all_packages_have_description() {
    for pkg in ALL_PKGS {
        let v = read_pkg(pkg);
        let desc = v["description"].as_str().unwrap_or("");
        assert!(
            desc.len() >= 10,
            "{pkg} description too short or missing (len={})",
            desc.len()
        );
    }
}

// ── Exports Resolution ──────────────────────────────────────────────

#[test]
fn all_exports_root_has_types_import_default() {
    for pkg in ALL_PKGS {
        let v = read_pkg(pkg);
        let root = &v["exports"]["."];
        assert!(
            root.is_object(),
            "{pkg} exports[\".\"] must be a conditional export object"
        );
        let obj = root.as_object().unwrap();
        assert!(
            obj.contains_key("types"),
            "{pkg} exports[\".\"] missing 'types' condition"
        );
        assert!(
            obj.contains_key("import") || obj.contains_key("default"),
            "{pkg} exports[\".\"] missing 'import' or 'default' condition"
        );
    }
}

#[test]
fn exports_types_path_ends_with_dts() {
    for pkg in ALL_PKGS {
        let v = read_pkg(pkg);
        let types_path = v["exports"]["."]["types"]
            .as_str()
            .unwrap_or_else(|| panic!("{pkg} missing exports[\".\"].types"));
        assert!(
            types_path.ends_with(".d.ts"),
            "{pkg} exports types path must end with .d.ts, got {types_path}"
        );
    }
}

#[test]
fn exports_import_path_ends_with_js() {
    for pkg in ALL_PKGS {
        let v = read_pkg(pkg);
        let root = v["exports"]["."].as_object().unwrap();
        let import_path = root
            .get("import")
            .or_else(|| root.get("default"))
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("{pkg} missing exports[\".\"].import/default"));
        assert!(
            import_path.ends_with(".js"),
            "{pkg} exports import path must end with .js, got {import_path}"
        );
    }
}

#[test]
fn main_and_types_fields_match_exports_root() {
    for pkg in ALL_PKGS {
        let v = read_pkg(pkg);
        let main = v["main"].as_str().unwrap();
        let types = v["types"].as_str().unwrap();

        let root = v["exports"]["."].as_object().unwrap();
        let export_import = root
            .get("import")
            .or_else(|| root.get("default"))
            .and_then(|v| v.as_str())
            .unwrap();
        let export_types = root["types"].as_str().unwrap();

        assert_eq!(
            main, export_import,
            "{pkg}: main ({main}) must match exports[\".\"].import ({export_import})"
        );
        assert_eq!(
            types, export_types,
            "{pkg}: types ({types}) must match exports[\".\"].types ({export_types})"
        );
    }
}

// ── Files Array Completeness ─────────────────────────────────────────

#[test]
fn higher_level_packages_files_array_covers_dist() {
    for pkg in &["browser", "react", "next"] {
        let v = read_pkg(pkg);
        let files: Vec<&str> = v["files"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|f| f.as_str())
            .collect();
        assert!(
            files.contains(&"dist") || files.iter().any(|f| f.starts_with("dist/")),
            "{pkg} files array must include 'dist' directory"
        );
    }
}

#[test]
fn browser_core_files_include_wasm_and_js() {
    let v = read_pkg("browser-core");
    let files: Vec<&str> = v["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f.as_str())
        .collect();

    let required = ["asupersync_bg.wasm", "abi-metadata.json"];
    for r in &required {
        assert!(files.contains(r), "browser-core files must include {r}");
    }

    // Must have at least one .js and one .d.ts
    assert!(
        files.iter().any(|f| f.ends_with(".js")),
        "browser-core files must include at least one .js file"
    );
    assert!(
        files.iter().any(|f| f.ends_with(".d.ts")),
        "browser-core files must include at least one .d.ts file"
    );
}

// ── Dependency Correctness ───────────────────────────────────────────

#[test]
fn dependency_versions_use_workspace_protocol() {
    let browser = read_pkg("browser");
    let bc_dep = browser["dependencies"]["@asupersync/browser-core"]
        .as_str()
        .unwrap();
    assert!(
        bc_dep.starts_with("workspace:"),
        "browser -> browser-core must use workspace protocol, got {bc_dep}"
    );

    let react = read_pkg("react");
    let br_dep = react["dependencies"]["@asupersync/browser"]
        .as_str()
        .unwrap();
    assert!(
        br_dep.starts_with("workspace:"),
        "react -> browser must use workspace protocol, got {br_dep}"
    );

    let next = read_pkg("next");
    let br_dep = next["dependencies"]["@asupersync/browser"]
        .as_str()
        .unwrap();
    assert!(
        br_dep.starts_with("workspace:"),
        "next -> browser must use workspace protocol, got {br_dep}"
    );
}

#[test]
fn no_package_depends_on_itself() {
    for pkg in ALL_PKGS {
        let v = read_pkg(pkg);
        let name = v["name"].as_str().unwrap();
        if let Some(deps) = v["dependencies"].as_object() {
            assert!(!deps.contains_key(name), "{pkg} must not depend on itself");
        }
    }
}

#[test]
fn dependency_graph_is_acyclic() {
    // Build adjacency list
    let mut edges: HashMap<String, Vec<String>> = HashMap::new();
    for pkg in ALL_PKGS {
        let v = read_pkg(pkg);
        let name = v["name"].as_str().unwrap().to_string();
        let deps: Vec<String> = v["dependencies"]
            .as_object()
            .map(|d| {
                d.keys()
                    .filter(|k| k.starts_with("@asupersync/"))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        edges.insert(name, deps);
    }

    // DFS cycle detection
    let mut visited: HashSet<String> = HashSet::new();
    let mut in_stack: HashSet<String> = HashSet::new();

    fn dfs(
        node: &str,
        edges: &HashMap<String, Vec<String>>,
        visited: &mut HashSet<String>,
        in_stack: &mut HashSet<String>,
    ) -> bool {
        if in_stack.contains(node) {
            return true; // cycle
        }
        if visited.contains(node) {
            return false;
        }
        visited.insert(node.to_string());
        in_stack.insert(node.to_string());
        if let Some(deps) = edges.get(node) {
            for dep in deps {
                if dfs(dep, edges, visited, in_stack) {
                    return true;
                }
            }
        }
        in_stack.remove(node);
        false
    }

    for pkg in edges.keys() {
        assert!(
            !dfs(pkg, &edges, &mut visited, &mut in_stack),
            "cycle detected in dependency graph involving {pkg}"
        );
    }
}

// ── Consumer Install Simulation ──────────────────────────────────────

#[test]
fn all_packages_have_keywords() {
    for pkg in ALL_PKGS {
        let v = read_pkg(pkg);
        let keywords = v["keywords"].as_array().expect("keywords must be array");
        assert!(
            keywords.len() >= 3,
            "{pkg} should have at least 3 keywords for npm discoverability"
        );
        // All must include "asupersync"
        let has_asupersync = keywords.iter().any(|k| k.as_str() == Some("asupersync"));
        assert!(has_asupersync, "{pkg} keywords must include 'asupersync'");
    }
}

#[test]
fn validate_script_exists() {
    let path = repo_root().join("scripts/validate_npm_pack_smoke.sh");
    assert!(path.exists(), "validate_npm_pack_smoke.sh must exist");
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("npm pack"), "must reference npm pack");
    assert!(
        content.contains("VALIDATION PASSED"),
        "must report validation result"
    );
}

// ── Version Consistency (consumer-facing) ────────────────────────────

#[test]
fn all_versions_are_valid_semver() {
    for pkg in ALL_PKGS {
        let v = read_pkg(pkg);
        let version = v["version"].as_str().unwrap();
        let parts: Vec<&str> = version.split('.').collect();
        assert!(
            parts.len() >= 3,
            "{pkg} version {version} must have at least major.minor.patch"
        );
        for (i, label) in ["major", "minor", "patch"].iter().enumerate() {
            assert!(
                parts[i].split('-').next().unwrap().parse::<u32>().is_ok(),
                "{pkg} version {version} has non-numeric {label} component"
            );
        }
    }
}
