use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn browser_core_package_manifest_declares_artifact_layout() {
    let package_json_path = workspace_root().join("packages/browser-core/package.json");
    let raw = fs::read_to_string(package_json_path).expect("read package.json");
    let manifest: Value = serde_json::from_str(&raw).expect("parse package.json");

    assert_eq!(manifest["main"], "./index.js");
    assert_eq!(manifest["module"], "./index.js");
    assert_eq!(manifest["types"], "./index.d.ts");
    assert_eq!(
        manifest["exports"]["./abi-metadata.json"],
        "./abi-metadata.json"
    );
    assert_eq!(
        manifest["exports"]["./debug-metadata.json"],
        "./debug-metadata.json"
    );
}

#[test]
fn browser_core_manifest_avoids_advertising_optional_or_missing_artifacts() {
    let package_dir = workspace_root().join("packages/browser-core");
    let raw = fs::read_to_string(package_dir.join("package.json")).expect("read package.json");
    let manifest: Value = serde_json::from_str(&raw).expect("parse package.json");
    let exports = manifest["exports"]
        .as_object()
        .expect("exports map required");
    let files = manifest["files"].as_array().expect("files array required");

    for forbidden in ["./asupersync.js.map", "./asupersync_bg.wasm.map"] {
        assert!(
            !exports.contains_key(forbidden),
            "package.json must not export optional artifact {forbidden} before it is staged"
        );
    }

    for forbidden in ["README.md", "asupersync.js.map", "asupersync_bg.wasm.map"] {
        assert!(
            !files.iter().any(|entry| entry.as_str() == Some(forbidden)),
            "files array must not advertise missing artifact {forbidden}"
        );
        assert!(
            !package_dir.join(forbidden).exists(),
            "test assumption drifted: missing artifact {forbidden} now exists on disk"
        );
    }
}

#[test]
fn artifact_emission_script_exists() {
    let script_path = workspace_root().join("scripts/build_browser_core_artifacts.sh");
    assert!(
        script_path.exists(),
        "artifact emission script must exist: {}",
        script_path.display()
    );

    let script = fs::read_to_string(&script_path).expect("read artifact emission script");
    assert!(
        script.contains("debug-metadata.json"),
        "script must emit debug metadata artifact"
    );
    assert!(
        script.contains("asupersync.js.map") && script.contains("asupersync_bg.wasm.map"),
        "script must handle JS and WASM source maps"
    );
}
