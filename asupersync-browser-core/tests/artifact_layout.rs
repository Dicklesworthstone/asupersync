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

    assert_eq!(manifest["main"], "./asupersync.js");
    assert_eq!(manifest["module"], "./asupersync.js");
    assert_eq!(manifest["types"], "./asupersync.d.ts");
    assert_eq!(
        manifest["exports"]["./abi-metadata.json"],
        "./abi-metadata.json"
    );
    assert_eq!(
        manifest["exports"]["./debug-metadata.json"],
        "./debug-metadata.json"
    );
    assert_eq!(
        manifest["exports"]["./asupersync.js.map"],
        "./asupersync.js.map"
    );
    assert_eq!(
        manifest["exports"]["./asupersync_bg.wasm.map"],
        "./asupersync_bg.wasm.map"
    );
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
