//! WASM Bundler/Runtime Compatibility Matrix Validation (WASM-9.4)
//!
//! Validates that the bundler compatibility matrix document exists,
//! covers all required bundlers/runtimes, cross-references the package
//! topology, documents packaging pipeline stages, and specifies
//! configuration requirements for all Tier 1 targets.
//!
//! Bead: asupersync-umelq.9.4

use std::path::Path;

fn load_matrix() -> String {
    std::fs::read_to_string("docs/wasm_bundler_compatibility_matrix.md")
        .expect("failed to load bundler compatibility matrix")
}

fn load_topology() -> String {
    std::fs::read_to_string("docs/wasm_typescript_package_topology.md")
        .expect("failed to load package topology")
}

fn load_release_channels() -> String {
    std::fs::read_to_string("docs/wasm_release_channel_strategy.md")
        .expect("failed to load release channel strategy")
}

fn load_ci_workflow() -> String {
    std::fs::read_to_string(".github/workflows/ci.yml").expect("failed to load CI workflow")
}

// ─── Document infrastructure ─────────────────────────────────────────

#[test]
fn matrix_document_exists() {
    assert!(
        Path::new("docs/wasm_bundler_compatibility_matrix.md").exists(),
        "Bundler compatibility matrix document must exist"
    );
}

#[test]
fn matrix_references_bead() {
    let doc = load_matrix();
    assert!(
        doc.contains("asupersync-umelq.9.4"),
        "Matrix must reference its own bead ID"
    );
}

#[test]
fn matrix_references_cross_documents() {
    let doc = load_matrix();
    let refs = [
        "wasm_typescript_package_topology.md",
        "wasm_release_channel_strategy.md",
        "wasm_quickstart_migration.md",
        "wasm_abi_contract.md",
        "wasm_abi_compatibility_policy.md",
    ];
    let mut missing = Vec::new();
    for r in &refs {
        if !doc.contains(r) {
            missing.push(*r);
        }
    }
    assert!(
        missing.is_empty(),
        "Matrix missing cross-references:\n{}",
        missing
            .iter()
            .map(|r| format!("  - {r}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn topology_documents_rust_crate_layout_and_pkg_staging() {
    let topology = load_topology();
    for marker in [
        "Rust Crate Layout and Artifact Provenance",
        "`asupersync-browser-core`",
        "`pkg/browser-core/<profile>/`",
        "`packages/browser-core/`",
    ] {
        assert!(
            topology.contains(marker),
            "Topology doc missing rust crate/artifact marker: {marker}"
        );
    }
}

#[test]
fn topology_pins_dedicated_worker_validation_artifacts() {
    let topology = load_topology();
    for marker in [
        "tests/fixtures/dedicated-worker-consumer",
        "scripts/validate_dedicated_worker_consumer.sh",
        "python3 scripts/run_browser_onboarding_checks.py --scenario worker",
        "target/e2e-results/dedicated_worker_consumer/<timestamp>/summary.json",
        "target/e2e-results/dedicated_worker_consumer/<timestamp>/browser-run.json",
        "scenario_inventory",
        "artifact pointers under `artifacts`",
    ] {
        assert!(
            topology.contains(marker),
            "Topology doc missing dedicated-worker validation marker: {marker}"
        );
    }
}

#[test]
fn matrix_documents_browser_core_producer_crate_and_staging_path() {
    let doc = load_matrix();
    for marker in [
        "`asupersync-browser-core`",
        "`pkg/browser-core/<profile>/`",
        "`--out-name asupersync`",
    ] {
        assert!(
            doc.contains(marker),
            "Bundler matrix missing producer/staging marker: {marker}"
        );
    }
}

// ─── Bundler coverage ────────────────────────────────────────────────

#[test]
fn matrix_covers_tier1_bundlers() {
    let doc = load_matrix();
    let tier1 = ["Vite", "Webpack", "Turbopack"];
    let mut missing = Vec::new();
    for bundler in &tier1 {
        if !doc.contains(bundler) {
            missing.push(*bundler);
        }
    }
    assert!(
        missing.is_empty(),
        "Matrix missing Tier 1 bundlers:\n{}",
        missing
            .iter()
            .map(|b| format!("  - {b}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn matrix_covers_tier2_bundlers() {
    let doc = load_matrix();
    assert!(
        doc.contains("esbuild"),
        "Matrix must cover esbuild (Tier 2)"
    );
}

#[test]
fn matrix_documents_tier_classification() {
    let doc = load_matrix();
    assert!(
        doc.contains("Tier 1") && doc.contains("Tier 2"),
        "Matrix must classify bundlers into tiers"
    );
}

#[test]
fn matrix_tier1_bundlers_have_config_requirements() {
    let doc = load_matrix();
    // Each Tier 1 bundler must have a configuration code block
    let configs = ["vite.config", "webpack.config", "next.config"];
    let mut missing = Vec::new();
    for cfg in &configs {
        if !doc.contains(cfg) {
            missing.push(*cfg);
        }
    }
    assert!(
        missing.is_empty(),
        "Matrix missing configuration examples:\n{}",
        missing
            .iter()
            .map(|c| format!("  - {c}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn matrix_esbuild_has_config_requirements() {
    let doc = load_matrix();
    assert!(
        doc.contains("esbuild.config") || doc.contains("esbuild.build"),
        "Matrix must include esbuild configuration example"
    );
}

#[test]
fn matrix_bundlers_have_known_constraints() {
    let doc = load_matrix();
    // Each bundler section must document known constraints
    assert!(
        doc.contains("Known constraints"),
        "Matrix must document known constraints for each bundler"
    );
    // Count occurrences — should be at least 4 (one per bundler)
    let count = doc.matches("Known constraints").count();
    assert!(
        count >= 4,
        "Matrix must document known constraints for all 4 bundlers, found {count}"
    );
}

// ─── Bundler property coverage ───────────────────────────────────────

#[test]
fn matrix_covers_required_bundler_properties() {
    let doc = load_matrix();
    let properties = [
        "Module format",
        "WASM loading",
        "Tree shaking",
        "Top-level await",
        "Dev server",
        "Production build",
    ];
    let mut missing = Vec::new();
    for prop in &properties {
        if !doc.contains(prop) {
            missing.push(*prop);
        }
    }
    assert!(
        missing.is_empty(),
        "Matrix missing bundler properties:\n{}",
        missing
            .iter()
            .map(|p| format!("  - {p}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ─── Runtime coverage ────────────────────────────────────────────────

#[test]
fn matrix_covers_browser_runtimes() {
    let doc = load_matrix();
    let browsers = ["Chrome", "Firefox", "Safari", "Edge"];
    let mut missing = Vec::new();
    for browser in &browsers {
        if !doc.contains(browser) {
            missing.push(*browser);
        }
    }
    assert!(
        missing.is_empty(),
        "Matrix missing browser runtime coverage:\n{}",
        missing
            .iter()
            .map(|b| format!("  - {b}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn matrix_covers_server_runtimes() {
    let doc = load_matrix();
    let runtimes = ["Node.js", "Deno", "Bun"];
    let mut missing = Vec::new();
    for rt in &runtimes {
        if !doc.contains(rt) {
            missing.push(*rt);
        }
    }
    assert!(
        missing.is_empty(),
        "Matrix missing server-side runtime coverage:\n{}",
        missing
            .iter()
            .map(|r| format!("  - {r}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn matrix_server_runtimes_reference_boundary_strategy() {
    let doc = load_matrix();
    assert!(
        doc.contains("wasm_typescript_package_topology.md")
            || doc.contains("boundary strategy")
            || doc.contains("bridge-only"),
        "Server runtime section must reference boundary strategy or topology doc"
    );
}

// ─── Package manager coverage ────────────────────────────────────────

#[test]
fn matrix_covers_supported_package_managers() {
    let doc = load_matrix();
    let managers = [
        "| `pnpm` 9.x",
        "| `npm` 10.x",
        "| `yarn` 4.x",
        "| `bun` 1.x",
    ];
    let mut missing = Vec::new();
    for manager in &managers {
        if !doc.contains(manager) {
            missing.push(*manager);
        }
    }
    assert!(
        missing.is_empty(),
        "Matrix missing package-manager coverage:\n{}",
        missing
            .iter()
            .map(|m| format!("  - {m}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn matrix_package_manager_section_references_workspace_contract() {
    let doc = load_matrix();
    for marker in [
        "packageManager",
        "pnpm-workspace.yaml",
        ".npmrc",
        "validate_npm_pack_smoke.sh",
    ] {
        assert!(
            doc.contains(marker),
            "Package-manager section missing workspace contract marker: {marker}"
        );
    }
}

// ─── Module resolution coverage ──────────────────────────────────────

#[test]
fn matrix_covers_module_resolution_modes() {
    let doc = load_matrix();
    for marker in ["moduleResolution", "| `bundler` |", "| `NodeNext` |"] {
        assert!(
            doc.contains(marker),
            "Matrix must document TypeScript resolver marker: {marker}"
        );
    }
}

#[test]
fn matrix_documents_resolver_examples_and_baseline_files() {
    let doc = load_matrix();
    for marker in [
        "tsconfig.base.json",
        "\"module\": \"ES2020\"",
        "\"moduleResolution\": \"bundler\"",
    ] {
        assert!(
            doc.contains(marker),
            "Matrix must document resolver baseline marker: {marker}"
        );
    }
}

#[test]
fn matrix_documents_unsupported_legacy_resolvers() {
    let doc = load_matrix();
    assert!(
        doc.contains("node16") || doc.contains("classic"),
        "Matrix must document unsupported legacy resolver modes"
    );
}

// ─── Module format coverage ──────────────────────────────────────────

#[test]
fn matrix_covers_esm() {
    let doc = load_matrix();
    assert!(
        doc.contains("ESM") && doc.contains("import"),
        "Matrix must document ESM module format"
    );
}

#[test]
fn matrix_covers_cjs() {
    let doc = load_matrix();
    assert!(
        doc.contains("CJS") && doc.contains("require"),
        "Matrix must document CJS module format"
    );
}

#[test]
fn matrix_documents_unsupported_formats() {
    let doc = load_matrix();
    assert!(
        doc.contains("IIFE") && doc.contains("UMD"),
        "Matrix must document that IIFE and UMD are not supported"
    );
}

// ─── Package artifacts ───────────────────────────────────────────────

#[test]
fn matrix_documents_package_artifacts() {
    let doc = load_matrix();
    let artifacts = [
        "asupersync_bg.wasm",
        "asupersync.js",
        "asupersync.d.ts",
        "package.json",
    ];
    let mut missing = Vec::new();
    for artifact in &artifacts {
        if !doc.contains(artifact) {
            missing.push(*artifact);
        }
    }
    assert!(
        missing.is_empty(),
        "Matrix missing package artifact documentation:\n{}",
        missing
            .iter()
            .map(|a| format!("  - {a}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn matrix_documents_entry_points() {
    let doc = load_matrix();
    assert!(
        doc.contains("\"main\"") && doc.contains("\"module\"") && doc.contains("\"types\""),
        "Matrix must document main, module, and types entry points"
    );
}

#[test]
fn matrix_documents_exports_map() {
    let doc = load_matrix();
    assert!(
        doc.contains("\"exports\"") && doc.contains("\"import\""),
        "Matrix must document package.json exports map"
    );
}

#[test]
fn matrix_documents_side_effects() {
    let doc = load_matrix();
    assert!(
        doc.contains("sideEffects"),
        "Matrix must document sideEffects: false for tree shaking"
    );
}

// ─── Packaging pipeline ──────────────────────────────────────────────

#[test]
fn matrix_documents_build_stages() {
    let doc = load_matrix();
    let stages = [
        "Profile Selection",
        "Rust Compilation",
        "Bindgen Generation",
        "Optimization",
        "Type Generation",
        "Package Assembly",
        "Validation",
        "Publishing",
    ];
    let mut missing = Vec::new();
    for stage in &stages {
        if !doc.contains(stage) {
            missing.push(*stage);
        }
    }
    assert!(
        missing.is_empty(),
        "Matrix missing pipeline stages:\n{}",
        missing
            .iter()
            .map(|s| format!("  - {s}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn matrix_documents_build_profiles() {
    let doc = load_matrix();
    let profiles = [
        "wasm-browser-dev",
        "wasm-browser-prod",
        "wasm-browser-deterministic",
        "wasm-browser-minimal",
    ];
    let mut missing = Vec::new();
    for profile in &profiles {
        if !doc.contains(profile) {
            missing.push(*profile);
        }
    }
    assert!(
        missing.is_empty(),
        "Matrix missing build profiles:\n{}",
        missing
            .iter()
            .map(|p| format!("  - {p}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn matrix_documents_profile_channel_mapping() {
    let doc = load_matrix();
    // Profile-to-channel mapping must be documented
    assert!(
        doc.contains("nightly") && doc.contains("canary") && doc.contains("stable"),
        "Matrix must document profile-to-channel mapping (nightly, canary, stable)"
    );
}

#[test]
fn matrix_documents_wasm_opt() {
    let doc = load_matrix();
    assert!(
        doc.contains("wasm-opt"),
        "Matrix must document wasm-opt optimization step"
    );
}

#[test]
fn matrix_documents_wasm_bindgen() {
    let doc = load_matrix();
    assert!(
        doc.contains("wasm-bindgen"),
        "Matrix must document wasm-bindgen step"
    );
}

// ─── Packaging invariants ────────────────────────────────────────────

#[test]
fn matrix_documents_packaging_invariants() {
    let doc = load_matrix();
    let invariants = [
        "Single profile per build",
        "Tree-shake safe",
        "Async WASM init",
        "ABI version embedded",
        "Fingerprint guard",
        "No native leakage",
        "Deterministic output",
    ];
    let mut missing = Vec::new();
    for inv in &invariants {
        if !doc.contains(inv) {
            missing.push(*inv);
        }
    }
    assert!(
        missing.is_empty(),
        "Matrix missing packaging invariants:\n{}",
        missing
            .iter()
            .map(|i| format!("  - {i}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn matrix_invariant_count() {
    let doc = load_matrix();
    // Should have exactly 7 numbered invariants
    let count = doc
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            trimmed.starts_with("1. **")
                || trimmed.starts_with("2. **")
                || trimmed.starts_with("3. **")
                || trimmed.starts_with("4. **")
                || trimmed.starts_with("5. **")
                || trimmed.starts_with("6. **")
                || trimmed.starts_with("7. **")
        })
        .count();
    assert!(
        count >= 7,
        "Matrix must have at least 7 packaging invariants, found {count}"
    );
}

// ─── Known issues ────────────────────────────────────────────────────

#[test]
fn matrix_documents_known_issues() {
    let doc = load_matrix();
    assert!(
        doc.contains("Known Issues") || doc.contains("Known issues"),
        "Matrix must have a known issues section"
    );
}

#[test]
fn matrix_known_issues_cover_cors() {
    let doc = load_matrix();
    assert!(
        doc.contains("CORS"),
        "Known issues must document CORS requirements for WASM streaming"
    );
}

#[test]
fn matrix_known_issues_cover_large_binary() {
    let doc = load_matrix();
    assert!(
        doc.contains("4MB") || doc.contains("large") || doc.contains("slow initial load"),
        "Known issues must document large WASM binary considerations"
    );
}

// ─── Validation commands ─────────────────────────────────────────────

#[test]
fn matrix_documents_validation_commands() {
    let doc = load_matrix();
    assert!(
        doc.contains("cargo check --target wasm32-unknown-unknown"),
        "Matrix must document cargo check validation commands for wasm32"
    );
    assert!(
        doc.contains("bash scripts/validate_npm_pack_smoke.sh"),
        "Matrix must document the package-manager/resolver smoke gate"
    );
}

#[test]
fn matrix_documents_test_command() {
    let doc = load_matrix();
    assert!(
        doc.contains("cargo test --test wasm_bundler_compatibility"),
        "Matrix must reference its own test suite"
    );
}

#[test]
fn matrix_documents_ci_certification_artifacts_and_repro_command() {
    let doc = load_matrix();
    for expected in [
        "artifacts/wasm_bundler_compatibility_summary.json",
        "artifacts/wasm_bundler_compatibility_test.log",
        "rch exec -- cargo test -p asupersync --test wasm_bundler_compatibility -- --nocapture",
    ] {
        assert!(
            doc.contains(expected),
            "Matrix must document CI certification evidence token: {expected}"
        );
    }
}

#[test]
fn ci_workflow_runs_bundler_compatibility_certification_gate() {
    let workflow = load_ci_workflow();
    for expected in [
        "WASM bundler compatibility certification",
        "cargo test -p asupersync --test wasm_bundler_compatibility -- --nocapture",
        "artifacts/wasm_bundler_compatibility_summary.json",
        "artifacts/wasm_bundler_compatibility_test.log",
        "wasm-bundler-compatibility-certification",
    ] {
        assert!(
            workflow.contains(expected),
            "CI workflow missing bundler compatibility certification token: {expected}"
        );
    }
}

// ─── Cross-reference consistency with topology ───────────────────────

#[test]
fn topology_bundlers_covered_in_matrix() {
    let topology = load_topology();
    let matrix = load_matrix();

    // Topology requires vite, webpack, next-turbopack
    if topology.contains("vite") {
        assert!(
            matrix.contains("Vite") || matrix.contains("vite"),
            "Matrix must cover vite (required by topology)"
        );
    }
    if topology.contains("webpack") {
        assert!(
            matrix.contains("Webpack") || matrix.contains("webpack"),
            "Matrix must cover webpack (required by topology)"
        );
    }
    if topology.contains("next-turbopack") || topology.contains("turbopack") {
        assert!(
            matrix.contains("Turbopack") || matrix.contains("turbopack"),
            "Matrix must cover turbopack (required by topology)"
        );
    }
}

#[test]
fn topology_module_modes_covered_in_matrix() {
    let topology = load_topology();
    let matrix = load_matrix();

    if topology.contains("esm") {
        assert!(
            matrix.contains("ESM"),
            "Matrix must cover ESM module mode (required by topology)"
        );
    }
    if topology.contains("cjs") {
        assert!(
            matrix.contains("CJS"),
            "Matrix must cover CJS module mode (required by topology)"
        );
    }
}

#[test]
fn topology_packages_referenced_in_matrix() {
    let matrix = load_matrix();
    assert!(
        matrix.contains("@asupersync/browser-core"),
        "Matrix must reference @asupersync/browser-core package"
    );
}

// ─── Cross-reference consistency with release channels ───────────────

#[test]
fn release_channels_consistent_with_matrix_profiles() {
    let channels = load_release_channels();
    let matrix = load_matrix();

    // Both documents should agree on channel names
    let channel_names = ["nightly", "canary", "stable"];
    for ch in &channel_names {
        let in_channels = channels.contains(ch);
        let in_matrix = matrix.contains(ch);
        assert!(
            !in_channels || in_matrix,
            "Channel '{ch}' in release strategy but not in bundler matrix"
        );
    }
}

// ─── Section structure ───────────────────────────────────────────────

#[test]
fn matrix_has_required_sections() {
    let doc = load_matrix();
    let sections = [
        "Purpose",
        "Package Artifacts",
        "Package Manager Compatibility Matrix",
        "TypeScript Module Resolution Compatibility",
        "Bundler Compatibility Matrix",
        "Runtime Compatibility Matrix",
        "Module Format Compatibility",
        "Packaging Pipeline",
        "Packaging Invariants",
        "Known Issues",
        "CI Matrix",
        "Cross-References",
    ];
    let mut missing = Vec::new();
    for section in &sections {
        if !doc.contains(section) {
            missing.push(*section);
        }
    }
    assert!(
        missing.is_empty(),
        "Matrix missing sections:\n{}",
        missing
            .iter()
            .map(|s| format!("  - {s}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
