//! ATP QUIC dependency audit gate contract test
//!
//! This test validates that the ATP native core remains self-contained
//! and does not depend on external QUIC stacks or Tokio runtime paths
//! in production profiles.
//!
//! Related to bead: asupersync-jaghjr (ATP-M5)

use std::process::Command;

#[test]
fn atp_dependency_audit_gate_passes() {
    // Run the ATP dependency audit script
    let output = Command::new("scripts/detect_forbidden_quic_deps.sh")
        .arg("--audit-only")
        .output()
        .expect("Failed to run ATP dependency audit script");

    // Check that the script passed (exit code 0)
    assert!(
        output.status.success(),
        "ATP dependency audit failed. This means forbidden QUIC stacks or Tokio dependencies \
        were detected in ATP native core profiles.\n\nStdout:\n{}\n\nStderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the success message is present
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ATP Dependency Audit PASSED"),
        "Expected success message not found in output: {}",
        stdout
    );

    // Verify no violations were reported
    assert!(
        stdout.contains("No forbidden QUIC stacks or Tokio runtime paths detected"),
        "Expected clean audit message not found in output: {}",
        stdout
    );
}

#[test]
fn atp_native_core_profiles_are_self_contained() {
    // Test each production profile individually to ensure they remain self-contained
    let profiles = [
        ("default-production", ""),
        ("metrics-production", "--features metrics"),
        ("quic-native", "--features quic"),
        ("http3-native", "--features http3"),
    ];

    for (profile_name, feature_args) in profiles {
        println!(
            "Testing profile: {} with args: {}",
            profile_name, feature_args
        );

        // Check for forbidden QUIC dependencies using cargo tree
        let mut cmd = Command::new("rch");
        cmd.args(["exec", "--"]).arg("env");

        // Set unique target directory for each profile
        let target_dir = format!(
            "/tmp/rch_target_atp_audit_{}",
            profile_name.replace("-", "_")
        );
        cmd.arg(format!("CARGO_TARGET_DIR={}", target_dir));

        cmd.args(["cargo", "tree", "-e", "normal", "-p", "asupersync"]);

        if !feature_args.is_empty() {
            cmd.args(feature_args.split_whitespace());
        }

        let output = cmd
            .output()
            .expect(&format!("Failed to run cargo tree for {}", profile_name));

        assert!(
            output.status.success(),
            "cargo tree failed for profile {}: {}",
            profile_name,
            String::from_utf8_lossy(&output.stderr)
        );

        let tree_output = String::from_utf8_lossy(&output.stdout);

        // Check for forbidden external QUIC stacks
        let forbidden_quic_crates = [
            "quinn",
            "quinn-proto",
            "quinn-udp",
            "quiche",
            "s2n-quic",
            "s2n-quic-core",
            "s2n-quic-transport",
            "h3-quinn",
            "h3-quiche",
            "msquic",
            "msquic-sys",
            "cloudflare-quic",
            "neqo-transport",
            "neqo-http3",
            "lsquic",
            "lsquic-sys",
        ];

        for crate_name in forbidden_quic_crates {
            assert!(
                !tree_output.contains(&format!("{} ", crate_name)),
                "Forbidden external QUIC crate '{}' found in {} dependency tree",
                crate_name,
                profile_name
            );
        }

        // Check for forbidden Tokio dependencies (production profiles only)
        if profile_name.contains("production") {
            let forbidden_tokio_crates = [
                "tokio ",
                "tokio-util ",
                "tokio-stream ",
                "tokio-tungstenite ",
                "hyper ",
                "reqwest ",
                "axum ",
                "tower-http ",
                "async-std ",
                "smol ",
            ];

            for crate_name in forbidden_tokio_crates {
                assert!(
                    !tree_output.contains(crate_name),
                    "Forbidden Tokio runtime crate '{}' found in {} dependency tree. \
                    Production profiles must maintain no-Tokio guarantee.",
                    crate_name.trim(),
                    profile_name
                );
            }
        }
    }
}

#[test]
fn cargo_toml_documents_quic_native_policy() {
    // Verify that Cargo.toml contains the documented policy against external QUIC stacks
    let cargo_toml = std::fs::read_to_string("Cargo.toml").expect("Failed to read Cargo.toml");

    assert!(
        cargo_toml.contains("QUIC/HTTP3 is intentionally native-only for ATP and the runtime core"),
        "Cargo.toml must document the native QUIC policy"
    );

    assert!(
        cargo_toml.contains("Do not add an external QUIC/H3 stack dependency here"),
        "Cargo.toml must contain warning against external QUIC dependencies"
    );
}

#[test]
fn audit_script_exists_and_is_executable() {
    use std::os::unix::fs::PermissionsExt;

    let script_path = "scripts/detect_forbidden_quic_deps.sh";
    let metadata = std::fs::metadata(script_path).expect("ATP dependency audit script must exist");

    assert!(metadata.is_file(), "Audit script must be a regular file");

    // Check that the script is executable (has execute permission)
    let permissions = metadata.permissions();
    assert!(
        permissions.mode() & 0o111 != 0,
        "Audit script must be executable"
    );
}

#[test]
fn audit_contract_exists() {
    // Verify that the contract file exists and is valid JSON
    let contract_path = "artifacts/atp_quic_dependency_audit_gate_contract_v1.json";
    let contract_content = std::fs::read_to_string(contract_path)
        .expect("ATP QUIC dependency audit gate contract must exist");

    // Parse as JSON to ensure it's valid
    let contract: serde_json::Value =
        serde_json::from_str(&contract_content).expect("Contract must be valid JSON");

    // Verify key contract fields
    assert_eq!(
        contract["bead_id"].as_str().unwrap(),
        "asupersync-jaghjr",
        "Contract must reference the correct bead ID"
    );

    assert_eq!(
        contract["contract_version"].as_str().unwrap(),
        "atp-quic-dependency-audit-gate-contract-v1",
        "Contract must have correct version"
    );

    // Verify enforcement policy is documented
    assert!(
        contract["enforcement_policy"]["principle"].is_string(),
        "Contract must document enforcement principle"
    );
}

#[cfg(test)]
mod integration {
    use super::*;

    #[test]
    fn proof_lane_manifest_includes_audit_gate() {
        // Verify that the proof lane manifest includes the new audit gate
        let manifest_content = std::fs::read_to_string("artifacts/proof_lane_manifest_v1.json")
            .expect("Proof lane manifest must exist");

        let manifest: serde_json::Value =
            serde_json::from_str(&manifest_content).expect("Manifest must be valid JSON");

        // Check that the guarantee ID is in required_guarantee_ids
        let required_ids = manifest["required_guarantee_ids"]
            .as_array()
            .expect("required_guarantee_ids must be an array");

        assert!(
            required_ids
                .iter()
                .any(|id| id.as_str() == Some("atp-native-self-contained")),
            "Proof lane manifest must include atp-native-self-contained guarantee"
        );

        // Check that the lane exists
        let lanes = manifest["lanes"]
            .as_array()
            .expect("lanes must be an array");

        let audit_lane = lanes
            .iter()
            .find(|lane| lane["lane_id"].as_str() == Some("atp-native-quic-dependency-audit"))
            .expect("Audit lane must exist in manifest");

        // Verify lane configuration
        assert_eq!(
            audit_lane["command"].as_str().unwrap(),
            "RCH_REQUIRE_REMOTE=1 rch exec -- scripts/detect_forbidden_quic_deps.sh"
        );

        assert_eq!(audit_lane["kind"].as_str().unwrap(), "dependency_audit");

        // Check that the guarantee exists
        let guarantees = manifest["guarantees"]
            .as_array()
            .expect("guarantees must be an array");

        let audit_guarantee = guarantees
            .iter()
            .find(|guarantee| {
                guarantee["guarantee_id"].as_str() == Some("atp-native-self-contained")
            })
            .expect("Audit guarantee must exist in manifest");

        assert!(
            audit_guarantee["description"]
                .as_str()
                .unwrap()
                .contains("no external QUIC stacks"),
            "Guarantee description must mention QUIC stacks"
        );
    }
}
