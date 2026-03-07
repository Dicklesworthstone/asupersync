//! Contract tests for JS/TS exports, type declarations, and module-resolution
//! entrypoints (asupersync-3qv04.8.3.1).
//!
//! Validates that the published package entrypoints look correct from the
//! perspective of JavaScript and TypeScript consumers before heavier
//! consumer-app validation starts.

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

// ── Export Map Structure ─────────────────────────────────────────────

#[test]
fn browser_core_exports_have_conditional_root_with_three_conditions() {
    let v = read_pkg("browser-core");
    let root = v["exports"]["."].as_object().expect("root must be object");
    assert!(root.contains_key("types"), "root export missing 'types'");
    assert!(root.contains_key("import"), "root export missing 'import'");
    assert!(
        root.contains_key("default"),
        "root export missing 'default'"
    );
}

#[test]
fn browser_core_types_export_is_separate_subpath() {
    let v = read_pkg("browser-core");
    let exports = v["exports"].as_object().unwrap();
    assert!(
        exports.contains_key("./types"),
        "browser-core must export ./types subpath for type-only imports"
    );
    let types_export = exports["./types"].as_object().unwrap();
    assert!(
        types_export.contains_key("types"),
        "./types export must have types condition"
    );
}

#[test]
fn browser_exports_tracing_subpath() {
    let v = read_pkg("browser");
    let exports = v["exports"].as_object().unwrap();
    if exports.contains_key("./tracing") {
        let tracing = exports["./tracing"].as_object().unwrap();
        assert!(
            tracing.contains_key("types"),
            "./tracing export must have types condition"
        );
        assert!(
            tracing.contains_key("import") || tracing.contains_key("default"),
            "./tracing export must have import or default condition"
        );
    }
    // ./tracing is optional; test passes if absent
}

#[test]
fn no_package_exports_package_json_subpath() {
    // Consumers should not be able to deep-import package.json
    for pkg in &["browser-core", "browser", "react", "next"] {
        let v = read_pkg(pkg);
        let exports = v["exports"].as_object().unwrap();
        assert!(
            !exports.contains_key("./package.json"),
            "{pkg} must not export ./package.json (prevents accidental dependency on internals)"
        );
    }
}

// ── Type Declaration Consistency ─────────────────────────────────────

#[test]
fn top_level_types_field_matches_exports_types() {
    for pkg in &["browser-core", "browser", "react", "next"] {
        let v = read_pkg(pkg);
        let top_types = v["types"].as_str().unwrap();
        let export_types = v["exports"]["."]["types"].as_str().unwrap();
        assert_eq!(
            top_types, export_types,
            "{pkg}: top-level 'types' ({top_types}) must match exports[\".\"].types ({export_types})"
        );
    }
}

#[test]
fn browser_core_types_file_listed_in_files_array() {
    let v = read_pkg("browser-core");
    let types_path = v["types"].as_str().unwrap().trim_start_matches("./");
    let files: Vec<&str> = v["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f.as_str())
        .collect();
    assert!(
        files.contains(&types_path),
        "browser-core types file {types_path} not in files array"
    );
}

#[test]
fn higher_level_packages_types_in_dist() {
    for pkg in &["browser", "react", "next"] {
        let v = read_pkg(pkg);
        let types = v["types"].as_str().unwrap();
        assert!(
            types.starts_with("./dist/"),
            "{pkg} types must be in dist/, got {types}"
        );
        assert!(
            types.ends_with(".d.ts"),
            "{pkg} types must end with .d.ts, got {types}"
        );
    }
}

// ── Module Resolution Patterns ───────────────────────────────────────

#[test]
fn all_packages_are_esm_with_module_field() {
    for pkg in &["browser-core", "browser", "react", "next"] {
        let v = read_pkg(pkg);
        assert_eq!(v["type"].as_str().unwrap(), "module", "{pkg} must be ESM");
        // module field should match main for ESM packages
        let main = v["main"].as_str().unwrap();
        let module = v["module"].as_str().unwrap_or(main);
        assert_eq!(
            main, module,
            "{pkg}: main and module should match for pure ESM packages"
        );
    }
}

#[test]
fn browser_core_main_is_js_not_wasm() {
    let v = read_pkg("browser-core");
    let main = v["main"].as_str().unwrap();
    assert!(
        main.ends_with(".js"),
        "browser-core main must be .js (not .wasm), got {main}"
    );
}

#[test]
fn higher_level_main_points_to_dist_index() {
    for pkg in &["browser", "react", "next"] {
        let v = read_pkg(pkg);
        let main = v["main"].as_str().unwrap();
        assert!(
            main.starts_with("./dist/") && main.ends_with(".js"),
            "{pkg} main must be ./dist/*.js, got {main}"
        );
    }
}

// ── Source File Presence for Higher-Level Packages ────────────────────

#[test]
fn browser_src_index_exports_from_browser_core() {
    let path = repo_root().join("packages/browser/src/index.ts");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    assert!(
        content.contains("@asupersync/browser-core"),
        "browser src/index.ts must import from @asupersync/browser-core"
    );
}

#[test]
fn react_src_index_exports_from_browser() {
    let path = repo_root().join("packages/react/src/index.ts");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    assert!(
        content.contains("@asupersync/browser"),
        "react src/index.ts must import from @asupersync/browser"
    );
}

#[test]
fn next_src_index_exports_from_browser() {
    let path = repo_root().join("packages/next/src/index.ts");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    assert!(
        content.contains("@asupersync/browser"),
        "next src/index.ts must import from @asupersync/browser"
    );
}

// ── TypeScript Config for Resolution ─────────────────────────────────

#[test]
fn browser_core_tsconfig_uses_composite() {
    let path = repo_root().join("packages/browser-core/tsconfig.json");
    let content = std::fs::read_to_string(&path).unwrap();
    let v: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(
        v["compilerOptions"]["composite"], true,
        "browser-core tsconfig must enable composite for project references"
    );
}

#[test]
fn higher_level_tsconfigs_reference_dependencies() {
    let browser_ts = repo_root().join("packages/browser/tsconfig.json");
    let content = std::fs::read_to_string(&browser_ts).unwrap();
    let v: serde_json::Value = serde_json::from_str(&content).unwrap();
    let refs = v["references"]
        .as_array()
        .expect("browser must have references");
    let ref_paths: Vec<&str> = refs.iter().filter_map(|r| r["path"].as_str()).collect();
    assert!(
        ref_paths.iter().any(|p| p.contains("browser-core")),
        "browser tsconfig must reference browser-core"
    );
}

#[test]
fn tsconfig_base_uses_bundler_resolution() {
    let path = repo_root().join("tsconfig.base.json");
    let content = std::fs::read_to_string(&path).unwrap();
    let v: serde_json::Value = serde_json::from_str(&content).unwrap();
    let resolution = v["compilerOptions"]["moduleResolution"]
        .as_str()
        .unwrap_or("");
    assert!(
        resolution == "bundler" || resolution == "Bundler",
        "tsconfig.base must use bundler moduleResolution for ESM exports support, got {resolution}"
    );
}

// ── Package Name Scoping ─────────────────────────────────────────────

#[test]
fn all_packages_are_scoped_under_asupersync() {
    for pkg in &["browser-core", "browser", "react", "next"] {
        let v = read_pkg(pkg);
        let name = v["name"].as_str().unwrap();
        assert!(
            name.starts_with("@asupersync/"),
            "{pkg} name must be scoped under @asupersync/, got {name}"
        );
    }
}

#[test]
fn package_directory_matches_scope_name() {
    for pkg in &["browser-core", "browser", "react", "next"] {
        let v = read_pkg(pkg);
        let name = v["name"].as_str().unwrap();
        let expected_suffix = name.split('/').last().unwrap();
        assert_eq!(
            expected_suffix, *pkg,
            "package directory {pkg} must match scope name suffix {expected_suffix}"
        );
    }
}
