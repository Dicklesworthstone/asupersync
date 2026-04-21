#![allow(warnings)]
#![allow(clippy::all)]
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

fn read_root_pkg() -> serde_json::Value {
    let path = repo_root().join("package.json");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    serde_json::from_str(&content).expect("invalid JSON")
}

fn read_tsconfig_base() -> serde_json::Value {
    let path = repo_root().join("tsconfig.base.json");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    serde_json::from_str(&content).expect("invalid JSON")
}

fn read_pkg_tsconfig(pkg: &str) -> serde_json::Value {
    let path = repo_root().join("packages").join(pkg).join("tsconfig.json");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    serde_json::from_str(&content).expect("invalid JSON")
}

const ALL_PKGS: &[&str] = &["browser-core", "browser", "react", "next"];

// ── Workspace and Resolver Contract ──────────────────────────────────

#[test]
fn root_workspace_pins_pnpm_package_manager() {
    let root = read_root_pkg();
    let package_manager = root["packageManager"]
        .as_str()
        .expect("root packageManager must be string");
    assert!(
        package_manager.starts_with("pnpm@"),
        "root packageManager must pin pnpm, got {package_manager}"
    );
}

#[test]
fn root_workspace_declares_node_and_pnpm_engines() {
    let root = read_root_pkg();
    let engines = root["engines"]
        .as_object()
        .expect("engines object required");
    assert!(
        engines.contains_key("node"),
        "root package.json must declare a node engine"
    );
    assert!(
        engines.contains_key("pnpm"),
        "root package.json must declare a pnpm engine"
    );
}

#[test]
fn root_workspace_scripts_use_pnpm_for_package_builds() {
    let root = read_root_pkg();
    let scripts = root["scripts"]
        .as_object()
        .expect("scripts object required");
    for key in ["build:packages", "build", "typecheck"] {
        let script = scripts[key]
            .as_str()
            .unwrap_or_else(|| panic!("root script {key} must be a string"));
        assert!(
            script.contains("pnpm"),
            "root script {key} must use pnpm for workspace package operations"
        );
    }
}

#[test]
fn root_validate_script_runs_npm_pack_smoke_validation() {
    let root = read_root_pkg();
    let scripts = root["scripts"]
        .as_object()
        .expect("scripts object required");
    let validate = scripts["validate"]
        .as_str()
        .expect("root validate script must be a string");
    assert!(
        validate.contains("bash scripts/validate_npm_pack_smoke.sh"),
        "root validate script must run scripts/validate_npm_pack_smoke.sh"
    );
}

#[test]
fn pnpm_workspace_and_npmrc_exist() {
    let workspace = repo_root().join("pnpm-workspace.yaml");
    let npmrc = repo_root().join(".npmrc");
    assert!(workspace.exists(), "pnpm-workspace.yaml must exist");
    assert!(npmrc.exists(), ".npmrc must exist");

    let workspace_text = std::fs::read_to_string(&workspace).unwrap();
    assert!(
        workspace_text.contains("packages/*"),
        "pnpm-workspace.yaml must enumerate packages/*"
    );

    let npmrc_text = std::fs::read_to_string(&npmrc).unwrap();
    assert!(
        npmrc_text.contains("enable-pre-post-scripts=true"),
        ".npmrc must retain deterministic package script policy"
    );
}

#[test]
fn tsconfig_base_uses_bundler_resolution() {
    let tsconfig = read_tsconfig_base();
    assert_eq!(
        tsconfig["compilerOptions"]["moduleResolution"].as_str(),
        Some("bundler"),
        "tsconfig.base.json must pin moduleResolution=bundler"
    );
    assert_eq!(
        tsconfig["compilerOptions"]["module"].as_str(),
        Some("ES2020"),
        "tsconfig.base.json must keep ESM module output"
    );
}

#[test]
fn package_tsconfigs_inherit_root_resolver_contract() {
    for pkg in ["browser", "react", "next"] {
        let tsconfig = read_pkg_tsconfig(pkg);
        assert_eq!(
            tsconfig["extends"].as_str(),
            Some("../../tsconfig.base.json"),
            "{pkg} tsconfig must extend the root TypeScript baseline"
        );
        let compiler_options = tsconfig["compilerOptions"].as_object().unwrap();
        assert!(
            !compiler_options.contains_key("moduleResolution"),
            "{pkg} tsconfig must not override moduleResolution"
        );
    }
}

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
            std::path::Path::new(import_path)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("js")),
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
        files.iter().any(|f| std::path::Path::new(f)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("js"))),
        "browser-core files must include at least one .js file"
    );
    assert!(
        files.iter().any(|f| f.ends_with(".d.ts")),
        "browser-core files must include at least one .d.ts file"
    );
}

#[test]
fn browser_core_files_array_only_advertises_existing_artifacts() {
    let v = read_pkg("browser-core");
    let package_dir = repo_root().join("packages/browser-core");
    let files = v["files"].as_array().expect("files array required");

    for entry in files {
        let rel = entry
            .as_str()
            .expect("browser-core files entries must be strings");
        let path = package_dir.join(rel);
        assert!(
            path.exists(),
            "browser-core files entry {rel} must exist on disk at {}",
            path.display()
        );
    }
}

// ── Dependency Correctness ───────────────────────────────────────────

#[test]
fn dependency_versions_use_workspace_protocol() {
    let browser = read_pkg("browser");
    let browser_core_dep = browser["dependencies"]["@asupersync/browser-core"]
        .as_str()
        .unwrap();
    assert!(
        browser_core_dep.starts_with("workspace:"),
        "browser -> browser-core must use workspace protocol, got {browser_core_dep}"
    );

    let react = read_pkg("react");
    let browser_dep = react["dependencies"]["@asupersync/browser"]
        .as_str()
        .unwrap();
    assert!(
        browser_dep.starts_with("workspace:"),
        "react -> browser must use workspace protocol, got {browser_dep}"
    );

    let next = read_pkg("next");
    let browser_dep_next = next["dependencies"]["@asupersync/browser"]
        .as_str()
        .unwrap();
    assert!(
        browser_dep_next.starts_with("workspace:"),
        "next -> browser must use workspace protocol, got {browser_dep_next}"
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

    #[allow(clippy::items_after_statements)]
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
        content.contains("packageManager") && content.contains("moduleResolution"),
        "validate script must check package-manager and resolver contracts"
    );
    assert!(
        content.contains("VALIDATION PASSED"),
        "must report validation result"
    );
}

#[test]
fn vite_vanilla_consumer_fixture_exists() {
    let fixture = repo_root().join("tests/fixtures/vite-vanilla-consumer");
    assert!(
        fixture.exists(),
        "Vite consumer fixture directory must exist"
    );

    for rel in [
        "package.json",
        "index.html",
        "vite.config.ts",
        "src/main.ts",
        "scripts/check-bundle.mjs",
    ] {
        let path = fixture.join(rel);
        assert!(path.exists(), "missing fixture file: {}", path.display());
    }
}

#[test]
fn vite_vanilla_fixture_depends_on_browser_package() {
    let path = repo_root().join("tests/fixtures/vite-vanilla-consumer/package.json");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    let v: serde_json::Value = serde_json::from_str(&content).expect("invalid fixture package");
    let dep = v["dependencies"]["@asupersync/browser"]
        .as_str()
        .expect("fixture must depend on @asupersync/browser");
    assert!(
        dep.starts_with("file:"),
        "fixture dependency should use local file path, got {dep}"
    );
}

#[test]
fn vite_vanilla_validation_script_exists_and_references_bundle_steps() {
    let path = repo_root().join("scripts/validate_vite_vanilla_consumer.sh");
    assert!(
        path.exists(),
        "validate_vite_vanilla_consumer.sh must exist"
    );
    let content = std::fs::read_to_string(&path).expect("failed to read validation script");
    for needle in [
        "tests/fixtures/vite-vanilla-consumer",
        "npm install",
        "npm run build",
        "npm run check:bundle",
        "asupersync-3qv04.6.1",
    ] {
        assert!(
            content.contains(needle),
            "validation script missing expected marker: {needle}"
        );
    }
}

#[test]
fn webpack_consumer_fixture_exists() {
    let fixture = repo_root().join("tests/fixtures/webpack-consumer");
    assert!(
        fixture.exists(),
        "Webpack consumer fixture directory must exist"
    );

    for rel in [
        "package.json",
        "webpack.config.mjs",
        "src/index.js",
        "scripts/check-bundle.mjs",
    ] {
        let path = fixture.join(rel);
        assert!(path.exists(), "missing fixture file: {}", path.display());
    }
}

#[test]
fn webpack_fixture_depends_on_browser_package() {
    let path = repo_root().join("tests/fixtures/webpack-consumer/package.json");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    let v: serde_json::Value = serde_json::from_str(&content).expect("invalid fixture package");
    let dep = v["dependencies"]["@asupersync/browser"]
        .as_str()
        .expect("fixture must depend on @asupersync/browser");
    assert!(
        dep.starts_with("file:"),
        "fixture dependency should use local file path, got {dep}"
    );
}

#[test]
fn webpack_validation_script_exists_and_references_bundle_steps() {
    let path = repo_root().join("scripts/validate_webpack_consumer.sh");
    assert!(path.exists(), "validate_webpack_consumer.sh must exist");
    let content = std::fs::read_to_string(&path).expect("failed to read validation script");
    for needle in [
        "tests/fixtures/webpack-consumer",
        "npm install",
        "npm run build",
        "npm run check:bundle",
        "asupersync-3qv04.6.2",
    ] {
        assert!(
            content.contains(needle),
            "validation script missing expected marker: {needle}"
        );
    }
}

#[test]
fn next_turbopack_consumer_fixture_exists() {
    let fixture = repo_root().join("tests/fixtures/next-turbopack-consumer");
    assert!(
        fixture.exists(),
        "Next/Turbopack consumer fixture directory must exist"
    );

    for rel in [
        "package.json",
        "next.config.mjs",
        "app/layout.jsx",
        "app/page.jsx",
        "app/client-runtime-panel.jsx",
        "app/api/server-bridge/route.js",
        "app/api/edge-bridge/route.js",
        "scripts/check-bundle.mjs",
    ] {
        let path = fixture.join(rel);
        assert!(path.exists(), "missing fixture file: {}", path.display());
    }
}

#[test]
fn next_turbopack_fixture_depends_on_next_package() {
    let path = repo_root().join("tests/fixtures/next-turbopack-consumer/package.json");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    let v: serde_json::Value = serde_json::from_str(&content).expect("invalid fixture package");
    let dep = v["dependencies"]["@asupersync/next"]
        .as_str()
        .expect("fixture must depend on @asupersync/next");
    assert!(
        dep.starts_with("file:"),
        "fixture dependency should use local file path, got {dep}"
    );
}

#[test]
fn next_turbopack_validation_script_exists_and_references_bundle_steps() {
    let path = repo_root().join("scripts/validate_next_turbopack_consumer.sh");
    assert!(
        path.exists(),
        "validate_next_turbopack_consumer.sh must exist"
    );
    let content = std::fs::read_to_string(&path).expect("failed to read validation script");
    for needle in [
        "tests/fixtures/next-turbopack-consumer",
        "npm install",
        "npm run build",
        "npm run check:bundle",
        "asupersync-3qv04.6.3",
    ] {
        assert!(
            content.contains(needle),
            "validation script missing expected marker: {needle}"
        );
    }
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
