//! Contract tests for the JS/TS package build tooling (asupersync-3qv04.4.3).
//!
//! These tests validate that the workspace configuration, package topology,
//! and build infrastructure are correctly wired without requiring wasm-pack
//! or pnpm to be installed.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

// ── Workspace Configuration ──────────────────────────────────────────

#[test]
fn pnpm_workspace_yaml_exists_and_lists_packages() {
    let path = repo_root().join("pnpm-workspace.yaml");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    assert!(
        content.contains("packages:"),
        "pnpm-workspace.yaml must declare packages"
    );
    assert!(
        content.contains("packages/*"),
        "pnpm-workspace.yaml must glob packages/*"
    );
}

#[test]
fn root_package_json_exists_with_workspace_scripts() {
    let path = repo_root().join("package.json");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    let v: serde_json::Value = serde_json::from_str(&content).expect("invalid JSON");

    assert_eq!(v["private"], true, "root package.json must be private");

    let scripts = v["scripts"].as_object().expect("scripts must be an object");
    for required in &[
        "build",
        "build:wasm",
        "build:packages",
        "clean",
        "typecheck",
        "validate",
    ] {
        assert!(
            scripts.contains_key(*required),
            "root package.json missing script: {required}"
        );
    }
}

#[test]
fn root_validate_script_runs_browser_package_build_validation() {
    let path = repo_root().join("package.json");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    let v: serde_json::Value = serde_json::from_str(&content).expect("invalid JSON");
    let validate = v["scripts"]["validate"]
        .as_str()
        .expect("root validate script must be a string");
    assert!(
        validate.contains("bash scripts/validate_package_build.sh"),
        "root validate script must run scripts/validate_package_build.sh"
    );
}

#[test]
fn npmrc_exists() {
    let path = repo_root().join(".npmrc");
    assert!(path.exists(), ".npmrc must exist");
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("enable-pre-post-scripts=true"));
}

#[test]
fn tsconfig_base_exists() {
    let path = repo_root().join("tsconfig.base.json");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    let v: serde_json::Value = serde_json::from_str(&content).expect("invalid JSON");
    assert!(
        v["compilerOptions"]["strict"] == true,
        "tsconfig.base.json must enable strict mode"
    );
}

// ── Package Topology ─────────────────────────────────────────────────

const PACKAGES: &[&str] = &["browser-core", "browser", "react", "next"];

#[test]
fn all_four_packages_have_package_json() {
    for pkg in PACKAGES {
        let path = repo_root().join("packages").join(pkg).join("package.json");
        assert!(path.exists(), "missing package.json for {pkg}");
    }
}

#[test]
fn all_four_packages_have_correct_name() {
    for pkg in PACKAGES {
        let path = repo_root().join("packages").join(pkg).join("package.json");
        let content = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        let expected = format!("@asupersync/{pkg}");
        assert_eq!(
            v["name"].as_str().unwrap(),
            expected,
            "package name mismatch for {pkg}"
        );
    }
}

#[test]
fn higher_level_packages_are_esm_modules() {
    for pkg in &["browser", "react", "next"] {
        let path = repo_root().join("packages").join(pkg).join("package.json");
        let content = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(v["type"].as_str().unwrap(), "module", "{pkg} must be ESM");
        assert!(v["main"].as_str().is_some(), "{pkg} must have main field");
        assert!(v["types"].as_str().is_some(), "{pkg} must have types field");
        assert!(v["exports"].is_object(), "{pkg} must have exports map");
    }
}

#[test]
fn higher_level_packages_have_build_scripts() {
    for pkg in &["browser", "react", "next"] {
        let path = repo_root().join("packages").join(pkg).join("package.json");
        let content = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        let scripts = v["scripts"].as_object().expect("scripts required");
        assert!(scripts.contains_key("build"), "{pkg} missing build script");
        assert!(
            scripts.contains_key("typecheck"),
            "{pkg} missing typecheck script"
        );
        assert!(scripts.contains_key("clean"), "{pkg} missing clean script");
    }
}

#[test]
fn higher_level_packages_have_typescript_source() {
    for pkg in &["browser", "react", "next"] {
        let path = repo_root()
            .join("packages")
            .join(pkg)
            .join("src")
            .join("index.ts");
        assert!(
            path.exists(),
            "missing src/index.ts for {pkg} ({})",
            path.display()
        );
    }
}

#[test]
fn higher_level_packages_have_tsconfig() {
    for pkg in &["browser", "react", "next"] {
        let path = repo_root().join("packages").join(pkg).join("tsconfig.json");
        assert!(path.exists(), "missing tsconfig.json for {pkg}");
        let content = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(
            v["extends"].as_str().is_some() || v["compilerOptions"].is_object(),
            "{pkg} tsconfig must extend base or define compilerOptions"
        );
    }
}

// ── Dependency Graph ─────────────────────────────────────────────────

#[test]
fn browser_depends_on_browser_core() {
    let v = read_pkg_json("browser");
    let dep = v["dependencies"]["@asupersync/browser-core"]
        .as_str()
        .expect("browser must depend on browser-core");
    assert!(
        dep.contains("workspace:") || dep.starts_with("0."),
        "browser-core dep should be workspace protocol or version"
    );
}

#[test]
fn react_depends_on_browser() {
    let v = read_pkg_json("react");
    let dep = v["dependencies"]["@asupersync/browser"]
        .as_str()
        .expect("react must depend on browser");
    assert!(
        dep.contains("workspace:") || dep.starts_with("0."),
        "browser dep should be workspace protocol or version"
    );
}

#[test]
fn react_declares_peer_react_dependency() {
    let v = read_pkg_json("react");
    let dep = v["peerDependencies"]["react"]
        .as_str()
        .expect("react package must declare peer dependency on react");
    assert!(
        dep.starts_with(">="),
        "react peer dependency should be a minimum semver range"
    );
}

#[test]
fn react_adapter_source_exposes_provider_and_hooks() {
    let path = repo_root().join("packages/react/src/index.ts");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    for marker in [
        "export function ReactRuntimeProvider",
        "export function useReactRuntimeContext",
        "export function useReactRuntime",
        "export function useReactRuntimeDiagnostics",
        "export function useReactScope",
        "StrictMode-safe init: stale bootstrap completions are ignored/closed.",
    ] {
        assert!(
            content.contains(marker),
            "react adapter source missing marker: {marker}"
        );
    }
}

#[test]
fn next_depends_on_browser() {
    let v = read_pkg_json("next");
    let dep = v["dependencies"]["@asupersync/browser"]
        .as_str()
        .expect("next must depend on browser");
    assert!(
        dep.contains("workspace:") || dep.starts_with("0."),
        "browser dep should be workspace protocol or version"
    );
}

#[test]
fn no_circular_dependencies() {
    // browser-core must not depend on any other @asupersync package
    let v = read_pkg_json("browser-core");
    let deps = v["dependencies"].as_object();
    if let Some(deps) = deps {
        for key in deps.keys() {
            assert!(
                !key.starts_with("@asupersync/") || key == "@asupersync/browser-core",
                "browser-core must not depend on {key}"
            );
        }
    }
}

// ── Build Script Infrastructure ──────────────────────────────────────

#[test]
fn build_browser_core_artifacts_script_exists() {
    let path = repo_root().join("scripts/build_browser_core_artifacts.sh");
    assert!(path.exists(), "build_browser_core_artifacts.sh must exist");
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("wasm-pack build"), "must invoke wasm-pack");
    assert!(
        content.contains("abi-metadata.json"),
        "must generate abi-metadata.json"
    );
}

#[test]
fn browser_core_release_profile_keeps_wasm_opt_bulk_memory_aware() {
    let path = repo_root()
        .join("asupersync-browser-core")
        .join("Cargo.toml");
    let content = std::fs::read_to_string(&path).unwrap();
    for marker in [
        "[package.metadata.wasm-pack.profile.release]",
        "wasm-opt = [\"-Oz\", \"--enable-bulk-memory\"",
    ] {
        assert!(
            content.contains(marker),
            "browser-core Cargo.toml missing release wasm-pack marker: {marker}"
        );
    }
}

#[test]
fn clean_script_exists() {
    let path = repo_root().join("scripts/clean_packages.sh");
    assert!(path.exists(), "clean_packages.sh must exist");
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(
        content.contains("pkg/browser-core"),
        "must clean staging dir"
    );
}

#[test]
fn validate_script_exists() {
    let path = repo_root().join("scripts/validate_package_build.sh");
    assert!(path.exists(), "validate_package_build.sh must exist");
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(
        content.contains("VALIDATION PASSED"),
        "must report validation result"
    );
}

// ── browser-core Package Structure ───────────────────────────────────

#[test]
fn browser_core_package_json_lists_wasm_artifacts_in_files() {
    let v = read_pkg_json("browser-core");
    let files: Vec<&str> = v["files"]
        .as_array()
        .expect("files array required")
        .iter()
        .filter_map(|f| f.as_str())
        .collect();
    assert!(files.contains(&"asupersync.js"), "must include JS entry");
    assert!(files.contains(&"asupersync.d.ts"), "must include TS decl");
    assert!(
        files.contains(&"asupersync_bg.wasm"),
        "must include WASM binary"
    );
    assert!(
        files.contains(&"abi-metadata.json"),
        "must include ABI metadata"
    );
}

#[test]
fn browser_core_exports_map_includes_wasm_and_metadata() {
    let v = read_pkg_json("browser-core");
    let exports = v["exports"].as_object().expect("exports map required");
    assert!(exports.contains_key("."), "must export root entry");
    assert!(
        exports.contains_key("./asupersync_bg.wasm"),
        "must export WASM"
    );
    assert!(
        exports.contains_key("./abi-metadata.json"),
        "must export ABI metadata"
    );
}

// ── Exports Map & Tree-Shake Safety (asupersync-3qv04.4.2) ──────────

#[test]
fn all_packages_have_side_effects_false() {
    for pkg in PACKAGES {
        let v = read_pkg_json(pkg);
        assert_eq!(
            v["sideEffects"], false,
            "{pkg} must have sideEffects: false for tree-shaking"
        );
    }
}

#[test]
fn no_internal_or_native_subpath_exports() {
    for pkg in PACKAGES {
        let v = read_pkg_json(pkg);
        if let Some(exports) = v["exports"].as_object() {
            for key in exports.keys() {
                assert!(
                    !key.contains("/internal"),
                    "{pkg} exports must not expose ./internal/* subpaths (found {key})"
                );
                assert!(
                    !key.contains("/native"),
                    "{pkg} exports must not expose ./native/* subpaths (found {key})"
                );
                assert!(
                    !key.contains("/src/"),
                    "{pkg} exports must not expose ./src/* subpaths (found {key})"
                );
            }
        }
    }
}

#[test]
fn exports_root_entry_types_condition_first() {
    // TypeScript requires "types" to be the first condition in conditional exports.
    // JSON object key order is preserved by Node.js but serde_json sorts keys,
    // so we check the raw file text for ordering.
    for pkg in PACKAGES {
        let path = repo_root().join("packages").join(pkg).join("package.json");
        let raw = std::fs::read_to_string(&path).unwrap();
        // Find the exports["."] block and verify "types" appears before "import"/"default"
        if let Some(types_pos) = raw.find("\"types\": \"./") {
            if let Some(import_pos) = raw.find("\"import\": \"./") {
                assert!(
                    types_pos < import_pos,
                    "{pkg}: 'types' condition must appear before 'import' in exports[\".\"] \
                     for correct TypeScript resolution"
                );
            }
            if let Some(default_pos) = raw.find("\"default\": \"./") {
                assert!(
                    types_pos < default_pos,
                    "{pkg}: 'types' condition must appear before 'default' in exports[\".\"]"
                );
            }
        }
    }
}

#[test]
fn higher_level_packages_only_export_safe_subpaths() {
    // Higher-level packages may export "." plus named public subpaths
    // (e.g. "./tracing"), but must never expose internal/native/src paths.
    for pkg in &["browser", "react", "next"] {
        let v = read_pkg_json(pkg);
        let exports = v["exports"].as_object().expect("exports required");
        assert!(exports.contains_key("."), "{pkg} must export root \".\"");
        for key in exports.keys() {
            assert!(
                !key.contains("/internal") && !key.contains("/native") && !key.contains("/src/"),
                "{pkg} exports must not expose internal paths (found {key})"
            );
            // All subpaths must be shallow (single segment after ./)
            if key != "." {
                let segments_count = key.trim_start_matches("./").split('/').count();
                assert_eq!(
                    segments_count, 1,
                    "{pkg} export {key} is too deep — only single-segment subpaths allowed"
                );
            }
        }
    }
}

#[test]
fn browser_core_exports_cover_all_published_artifacts() {
    let v = read_pkg_json("browser-core");
    let exports = v["exports"].as_object().expect("exports required");
    let files: Vec<&str> = v["files"]
        .as_array()
        .expect("files required")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();

    // Collect all file paths referenced by any export (direct or conditional)
    let mut exported_files: Vec<String> = Vec::new();
    for (_key, val) in exports {
        if let Some(s) = val.as_str() {
            exported_files.push(s.trim_start_matches("./").to_string());
        } else if let Some(obj) = val.as_object() {
            for (_cond, path) in obj {
                if let Some(p) = path.as_str() {
                    exported_files.push(p.trim_start_matches("./").to_string());
                }
            }
        }
    }

    // Every non-metadata file in "files" should be reachable through exports
    // (directly or as a transitive dependency of an exported entry)
    let metadata_files = [
        "README.md",
        "asupersync_bg.wasm.d.ts", // TS ambient declaration, not a direct import
        "asupersync.d.ts",         // wasm-bindgen generated decl, re-exported via index.d.ts
    ];
    for file in &files {
        if metadata_files.contains(file) {
            continue;
        }
        let is_exported = exported_files.iter().any(|e| e == file);
        assert!(
            is_exported,
            "browser-core file {file} is in 'files' but not reachable via any export"
        );
    }
}

#[test]
fn browser_core_exports_only_reference_published_files() {
    let v = read_pkg_json("browser-core");
    let exports = v["exports"].as_object().expect("exports required");
    let files: Vec<String> = v["files"]
        .as_array()
        .expect("files required")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .map(str::to_string)
        .collect();

    for (key, val) in exports {
        if key == "." {
            // Root entry references files via conditional export object
            if let Some(obj) = val.as_object() {
                for (_cond, path) in obj {
                    if let Some(p) = path.as_str() {
                        let bare = p.trim_start_matches("./");
                        assert!(
                            files.contains(&bare.to_string()),
                            "exports root condition references {p} not in files array"
                        );
                    }
                }
            }
        } else if let Some(target) = val.as_str() {
            let bare = target.trim_start_matches("./");
            assert!(
                files.contains(&bare.to_string()),
                "exports key {key} -> {target} references file not in files array"
            );
        }
    }
}

#[test]
fn browser_core_is_esm_module() {
    let v = read_pkg_json("browser-core");
    assert_eq!(
        v["type"].as_str().unwrap(),
        "module",
        "browser-core must be ESM"
    );
}

#[test]
fn all_packages_have_publish_config_public() {
    for pkg in PACKAGES {
        let v = read_pkg_json(pkg);
        assert_eq!(
            v["publishConfig"]["access"].as_str().unwrap(),
            "public",
            "{pkg} must have publishConfig.access = public"
        );
    }
}

// ── Version Consistency ──────────────────────────────────────────────

#[test]
fn all_packages_share_same_version() {
    let versions: Vec<(String, String)> = PACKAGES
        .iter()
        .map(|pkg| {
            let v = read_pkg_json(pkg);
            (pkg.to_string(), v["version"].as_str().unwrap().to_string())
        })
        .collect();
    let first = &versions[0].1;
    for (pkg, ver) in &versions {
        assert_eq!(
            ver, first,
            "version mismatch: {pkg} has {ver}, expected {first}"
        );
    }
}

// ── Mandatory Package Discovery (asupersync-3qv04.4.4) ──────────────

#[test]
fn policy_enforcement_mode_is_mandatory() {
    let path = repo_root().join(".github/wasm_typescript_package_policy.json");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    let v: serde_json::Value = serde_json::from_str(&content).expect("invalid JSON");
    assert_eq!(
        v["enforcement_mode"].as_str().unwrap(),
        "mandatory",
        "policy enforcement_mode must be 'mandatory' (not skippable)"
    );
}

#[test]
fn policy_required_packages_match_actual_packages() {
    let path = repo_root().join(".github/wasm_typescript_package_policy.json");
    let content = std::fs::read_to_string(&path).unwrap();
    let v: serde_json::Value = serde_json::from_str(&content).unwrap();

    let required: Vec<&str> = v["required_packages"]
        .as_array()
        .expect("required_packages must be array")
        .iter()
        .filter_map(|p| p.as_str())
        .collect();

    // Every required package must have a real package.json
    for pkg_name in &required {
        let dir_name = pkg_name.split('/').next_back().unwrap();
        let pkg_path = repo_root()
            .join("packages")
            .join(dir_name)
            .join("package.json");
        assert!(
            pkg_path.exists(),
            "required package {pkg_name} has no manifest at {}",
            pkg_path.display()
        );

        // Verify the name in the manifest matches
        let content = std::fs::read_to_string(&pkg_path).unwrap();
        let manifest: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            manifest["name"].as_str().unwrap(),
            *pkg_name,
            "manifest name mismatch for {pkg_name}"
        );
    }
}

#[test]
fn no_undiscovered_packages_in_workspace() {
    // Every directory in packages/ must be listed in the policy
    let path = repo_root().join(".github/wasm_typescript_package_policy.json");
    let content = std::fs::read_to_string(&path).unwrap();
    let v: serde_json::Value = serde_json::from_str(&content).unwrap();

    let required: std::collections::HashSet<String> = v["required_packages"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p.as_str())
        .map(std::string::ToString::to_string)
        .collect();

    let packages_dir = repo_root().join("packages");
    if packages_dir.exists() {
        for entry in std::fs::read_dir(&packages_dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                let pkg_json = entry.path().join("package.json");
                if pkg_json.exists() {
                    let content = std::fs::read_to_string(&pkg_json).unwrap();
                    let manifest: serde_json::Value = serde_json::from_str(&content).unwrap();
                    let name = manifest["name"].as_str().unwrap().to_string();
                    assert!(
                        required.contains(&name),
                        "package {name} in packages/{dir_name}/ is not in policy required_packages"
                    );
                }
            }
        }
    }
}

#[test]
fn strategy_doc_enforces_mandatory_discovery() {
    let path = repo_root().join("docs/wasm_release_channel_strategy.md");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    assert!(
        content.contains("Missing package manifests are a hard release-blocking failure"),
        "strategy doc must enforce mandatory package discovery"
    );
    assert!(
        !content.contains("controlled skip"),
        "strategy doc must not contain 'controlled skip' language"
    );
}

// ── Helpers ──────────────────────────────────────────────────────────

fn read_pkg_json(pkg: &str) -> serde_json::Value {
    let path = repo_root().join("packages").join(pkg).join("package.json");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("cannot read {}", path.display()));
    serde_json::from_str(&content).expect("invalid JSON")
}
