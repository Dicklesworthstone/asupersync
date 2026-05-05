//! Contract tests for the maintained React example fixture (asupersync-3qv04.9.3.2).
//!
//! This suite enforces that the React example lane remains present and wired to
//! the supported provider/hook adapter and deterministic validation script.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn react_consumer_fixture_exists_with_required_files() {
    let fixture = repo_root().join("tests/fixtures/react-consumer");
    assert!(
        fixture.exists(),
        "React consumer fixture directory must exist"
    );

    for rel in [
        "README.md",
        "package.json",
        "index.html",
        "vite.config.ts",
        "tsconfig.json",
        "src/main.tsx",
        "scripts/check-bundle.mjs",
    ] {
        let path = fixture.join(rel);
        assert!(path.exists(), "missing fixture file: {}", path.display());
    }
}

#[test]
fn react_fixture_declares_expected_dependencies() {
    let path = repo_root().join("tests/fixtures/react-consumer/package.json");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    let v: serde_json::Value = serde_json::from_str(&content).expect("invalid fixture package");

    let runtime_dep = v["dependencies"]["@asupersync/react"]
        .as_str()
        .expect("fixture must depend on @asupersync/react");
    assert!(
        runtime_dep.starts_with("file:"),
        "fixture dependency should use local file path, got {runtime_dep}"
    );

    for dep in ["react", "react-dom"] {
        assert!(
            v["dependencies"][dep].as_str().is_some(),
            "fixture must declare dependency: {dep}"
        );
    }
}

#[test]
fn react_fixture_source_uses_provider_and_hooks() {
    let path = repo_root().join("tests/fixtures/react-consumer/src/main.tsx");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));

    for marker in [
        "ReactRuntimeProvider",
        "useReactRuntimeContext",
        "useReactRuntimeDiagnostics",
        "useReactScope",
        "React.StrictMode",
    ] {
        assert!(
            content.contains(marker),
            "fixture source missing expected marker: {marker}"
        );
    }
}

#[test]
fn react_validation_script_exists_and_references_required_steps() {
    let path = repo_root().join("scripts/validate_react_consumer.sh");
    assert!(path.exists(), "validate_react_consumer.sh must exist");
    let content = std::fs::read_to_string(&path).expect("failed to read validation script");

    for needle in [
        "tests/fixtures/react-consumer",
        "npm install",
        "npm run build",
        "npm run check:bundle",
        "packages/react/dist/index.js",
        "asupersync-3qv04.9.3.2",
    ] {
        assert!(
            content.contains(needle),
            "validation script missing expected marker: {needle}"
        );
    }
}

#[test]
fn react_adapter_threads_runtime_options_global_object_into_support_diagnostics() {
    let path = repo_root().join("packages/react/src/index.ts");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));

    for marker in [
        "export function detectReactRuntimeSupport(",
        "globalObject: Record<string, unknown> | undefined = undefined,",
        "const browserDiagnostics = detectBrowserRuntimeSupport(globalObject);",
        "const globalObject = runtimeOptions?.globalObject;",
        "() => detectReactRuntimeSupport(globalObject),",
        "const diagnosticsSnapshot = detectReactRuntimeSupport(globalObject);",
        "const consumerVersionMajor = runtimeOptions?.consumerVersion?.major ?? null;",
        "const consumerVersionMinor = runtimeOptions?.consumerVersion?.minor ?? null;",
        "const healthPolicyCooldownMs = runtimeOptions?.healthPolicy?.cooldownMs ?? null;",
        "const healthPolicyMaxConsecutiveFailures =",
    ] {
        assert!(
            content.contains(marker),
            "React adapter source must preserve runtimeOptions/globalObject diagnostics alignment marker: {marker}"
        );
    }

    assert!(
        !content.contains("}, [reloadNonce, runtimeOptions]);"),
        "React adapter source must not key provider churn on raw runtimeOptions identity"
    );
}
