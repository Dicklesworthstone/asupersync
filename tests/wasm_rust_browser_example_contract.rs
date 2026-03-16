//! Contract tests for the maintained Rust-browser consumer fixture (`asupersync-4l9iw.2`).
//!
//! This suite keeps the repository-maintained Rust-authored browser example
//! wired to a real wasm package layout without implying broad public
//! `RuntimeBuilder` parity for external Rust consumers.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn rust_browser_consumer_fixture_exists_with_required_files() {
    let fixture = repo_root().join("tests/fixtures/rust-browser-consumer");
    assert!(
        fixture.exists(),
        "Rust browser consumer fixture directory must exist"
    );

    for rel in [
        "README.md",
        "package.json",
        "index.html",
        "vite.config.ts",
        "src/main.ts",
        "scripts/check-bundle.mjs",
        "scripts/check-browser-run.mjs",
        "crate/Cargo.toml",
        "crate/src/lib.rs",
    ] {
        let path = fixture.join(rel);
        assert!(path.exists(), "missing fixture file: {}", path.display());
    }
}

#[test]
fn rust_browser_consumer_crate_declares_expected_dependencies() {
    let path = repo_root().join("tests/fixtures/rust-browser-consumer/crate/Cargo.toml");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));

    for marker in [
        "asupersync = { path = \"../../../..\", default-features = false, features = [\"wasm-browser-dev\"] }",
        "wasm-bindgen = \"0.2\"",
        "serde-wasm-bindgen = \"0.6\"",
        "web-sys = { version = \"0.3\", features = [\"Document\", \"Window\"] }",
    ] {
        assert!(
            content.contains(marker),
            "crate manifest missing expected marker: {marker}"
        );
    }
}

#[test]
fn rust_browser_fixture_source_uses_provider_helpers_and_structured_teardown() {
    let path = repo_root().join("tests/fixtures/rust-browser-consumer/crate/src/lib.rs");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));

    for marker in [
        "ReactProviderState",
        "create_child_scope",
        "spawn_task",
        "complete_task",
        ".unmount()",
        "WasmAbiSymbol::TaskCancel",
        "repository_maintained_rust_browser_fixture",
    ] {
        assert!(
            content.contains(marker),
            "fixture source missing expected marker: {marker}"
        );
    }
}

#[test]
fn rust_browser_fixture_frontend_imports_generated_pkg() {
    let path = repo_root().join("tests/fixtures/rust-browser-consumer/src/main.ts");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));

    for marker in [
        "../pkg/asupersync_rust_browser_consumer_fixture.js",
        "run_rust_browser_consumer_demo",
        "\"rust-browser-consumer\"",
    ] {
        assert!(
            content.contains(marker),
            "frontend source missing expected marker: {marker}"
        );
    }
}

#[test]
fn rust_browser_validation_script_exists_and_offloads_wasm_builds_via_rch() {
    let path = repo_root().join("scripts/validate_rust_browser_consumer.sh");
    assert!(
        path.exists(),
        "validate_rust_browser_consumer.sh must exist"
    );
    let content = std::fs::read_to_string(&path).expect("failed to read validation script");

    for needle in [
        "tests/fixtures/rust-browser-consumer",
        "CRATE_DIR=\"${FIXTURE_DIR}/crate\"",
        "WORK_DIR=\"$(mktemp -d \"${RUN_DIR}/work.XXXXXX\")\"",
        "PKG_DIR=\"${WORK_DIR}/pkg\"",
        "CARGO_TARGET_DIR=\"${RUN_DIR}/cargo-target\"",
        "BROWSER_RUN_FILE=\"${RUN_DIR}/browser-run.json\"",
        "rch exec -- env CARGO_TARGET_DIR=\"${CARGO_TARGET_DIR}\" wasm-pack build",
        "npm install",
        "npm run build",
        "npm run check:bundle",
        "npm run check:browser -- \"${BROWSER_RUN_FILE}\"",
        "\"real_browser_run_ok\": browser_run[\"status\"] == \"ok\"",
        "\"ready_phase_is_ready\": browser_run[\"ready_phase\"] == \"ready\"",
        "\"disposed_phase_is_disposed\": browser_run[\"disposed_phase\"] == \"disposed\"",
        "\"completed_task_outcome_is_ok\": browser_run[\"completed_task_outcome\"] == \"ok\"",
        "\"cancel_event_count_is_one\": browser_run[\"cancel_event_count\"] == 1",
        "\"event_symbols_include_task_cancel\": \"task_cancel\" in browser_run[\"event_symbols\"]",
        "\"capabilities_has_webassembly\": browser_run[\"capabilities\"][\"has_webassembly\"] is True",
        "L6-RUST-BROWSER-CONSUMER",
        "asupersync-4l9iw.2",
    ] {
        assert!(
            content.contains(needle),
            "validation script missing expected marker: {needle}"
        );
    }
}

#[test]
fn rust_browser_fixture_uses_relative_vite_base_and_portable_bundle_checks() {
    let vite_config = repo_root().join("tests/fixtures/rust-browser-consumer/vite.config.ts");
    let vite_content = std::fs::read_to_string(&vite_config)
        .unwrap_or_else(|_| panic!("missing {}", vite_config.display()));
    assert!(
        vite_content.contains("base: \"./\""),
        "vite config must pin a relative base for subpath/file portability"
    );

    let bundle_check =
        repo_root().join("tests/fixtures/rust-browser-consumer/scripts/check-bundle.mjs");
    let bundle_content = std::fs::read_to_string(&bundle_check)
        .unwrap_or_else(|_| panic!("missing {}", bundle_check.display()));
    assert!(
        bundle_content.contains("(?:\\.\\/)?assets\\/"),
        "bundle check must accept relative hashed asset references"
    );
}

#[test]
fn rust_browser_fixture_declares_browser_run_check_and_headless_contract() {
    let package_json = repo_root().join("tests/fixtures/rust-browser-consumer/package.json");
    let package_content = std::fs::read_to_string(&package_json)
        .unwrap_or_else(|_| panic!("missing {}", package_json.display()));
    for marker in [
        "\"check:browser\": \"node ./scripts/check-browser-run.mjs\"",
        "\"playwright-core\": \"^1.51.1\"",
    ] {
        assert!(
            package_content.contains(marker),
            "fixture package must preserve browser-run marker: {marker}"
        );
    }

    let browser_check =
        repo_root().join("tests/fixtures/rust-browser-consumer/scripts/check-browser-run.mjs");
    let browser_content = std::fs::read_to_string(&browser_check)
        .unwrap_or_else(|_| panic!("missing {}", browser_check.display()));
    for marker in [
        "import { chromium } from \"playwright-core\";",
        "application/wasm",
        "path.relative(distDir, resolved)",
        "#status",
        "RUST-BROWSER-CONSUMER",
        "repository_maintained_rust_browser_fixture",
        "diagnostics_clean",
        "ready_phase === \"ready\"",
        "disposed_phase === \"disposed\"",
        "child_scope_count_before_unmount === 1",
        "active_task_count_before_unmount === 1",
        "completed_task_outcome === \"ok\"",
        "cancel_event_count === 1",
        "parsed.event_symbols.includes(symbol)",
        "parsed.capabilities?.has_window === true",
        "parsed.capabilities?.has_document === true",
        "parsed.capabilities?.has_webassembly === true",
        "status: \"error\"",
    ] {
        assert!(
            browser_content.contains(marker),
            "browser-run checker missing expected marker: {marker}"
        );
    }
}
