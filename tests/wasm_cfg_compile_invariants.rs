//! WASM cfg/profile compile invariants (3qv04.8.2.1).

#![allow(missing_docs)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const WASM_PROFILES: &[&str] = &[
    "wasm-browser-minimal",
    "wasm-browser-dev",
    "wasm-browser-prod",
    "wasm-browser-deterministic",
];

const LEAK_FRONTIER_FILES: &[&str] = &[
    "src/config.rs",
    "src/http/h1/listener.rs",
    "src/http/h1/server.rs",
    "src/net/tcp/mod.rs",
    "src/net/tcp/socket.rs",
    "src/runtime/reactor/source.rs",
    "src/trace/file.rs",
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn cargo_bin() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string())
}

fn render_output(output: &Output) -> String {
    format!(
        "status: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn run_cargo_check(args: &[&str], target_dir: &str) -> Output {
    Command::new(cargo_bin())
        .current_dir(repo_root())
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_TARGET_DIR", target_dir)
        .args(args)
        .output()
        .expect("failed to spawn cargo")
}

fn parse_feature_enables(manifest: &str, feature: &str) -> Vec<String> {
    let mut in_features = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_features = trimmed == "[features]";
            continue;
        }
        if !in_features || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((name, rest)) = trimmed.split_once('=') else {
            continue;
        };
        if name.trim() != feature {
            continue;
        }
        let start = rest
            .find('[')
            .expect("feature enables must be a TOML array");
        let end = rest[start..]
            .find(']')
            .expect("feature enable array must close on the same line");
        let body = &rest[start + 1..start + end];
        return body
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(|item| item.trim_matches('"').to_string())
            .collect();
    }
    panic!("feature `{feature}` not found in [features]");
}

#[test]
fn wasm_browser_profiles_include_runtime_core_and_forbid_native_runtime() {
    let manifest = std::fs::read_to_string(repo_root().join("Cargo.toml"))
        .expect("Cargo.toml must be readable");
    for profile in WASM_PROFILES {
        let enables = parse_feature_enables(&manifest, profile);
        assert!(
            enables.iter().any(|name| name == "runtime-core"),
            "{profile} must enable runtime-core so default-features = false, features = [{profile}] is self-sufficient; omitting it was the unresolved-serde wasm consumer defect"
        );
        assert!(
            !enables.iter().any(|name| name == "native-runtime"),
            "{profile} must not enable native-runtime (forbidden on wasm32)"
        );
    }
    let naive_prod = ["wasm-runtime", "browser-io"];
    let prod = parse_feature_enables(&manifest, "wasm-browser-prod");
    assert_ne!(
        prod.iter().map(String::as_str).collect::<Vec<_>>(),
        naive_prod,
        "the naive wasm-browser-prod list without runtime-core must not return"
    );
    let desktop = parse_feature_enables(&manifest, "desktop-runtime-profile");
    assert!(
        desktop.iter().any(|name| name == "runtime-core"),
        "desktop-runtime-profile must keep runtime-core"
    );
    assert!(
        desktop.iter().any(|name| name == "native-runtime"),
        "desktop-runtime-profile must keep native-runtime"
    );
}

#[test]
fn canonical_wasm_profiles_match_browser_matrix() {
    let mut profiles = WASM_PROFILES.to_vec();
    profiles.sort_unstable();
    profiles.dedup();
    assert_eq!(
        profiles.len(),
        WASM_PROFILES.len(),
        "canonical wasm profile list must stay unique"
    );
    assert_eq!(
        WASM_PROFILES,
        &[
            "wasm-browser-minimal",
            "wasm-browser-dev",
            "wasm-browser-prod",
            "wasm-browser-deterministic",
        ]
    );
}

#[test]
fn known_native_leak_frontier_files_exist() {
    for file in LEAK_FRONTIER_FILES {
        assert!(
            Path::new(file).exists(),
            "expected hotspot file to exist: {file}"
        );
    }
}

#[test]
fn leak_frontier_covers_prior_regressions() {
    for expected in [
        "src/config.rs",
        "src/runtime/reactor/source.rs",
        "src/net/tcp/socket.rs",
        "src/trace/file.rs",
    ] {
        assert!(
            LEAK_FRONTIER_FILES.contains(&expected),
            "leak frontier must include prior regression hotspot: {expected}"
        );
    }
}

#[test]
#[ignore = "runs cargo check across the canonical wasm profile matrix; invoke through rch"]
fn wasm_profile_matrix_compile_closure_holds() {
    for profile in WASM_PROFILES {
        let target_dir = format!("/tmp/asupersync-wasm-cfg-{profile}-{}", std::process::id());
        let output = run_cargo_check(
            &[
                "check",
                "-p",
                "asupersync",
                "--lib",
                "--target",
                "wasm32-unknown-unknown",
                "--no-default-features",
                "--features",
                profile,
            ],
            &target_dir,
        );
        assert!(
            output.status.success(),
            "wasm profile `{profile}` regressed; expected native surfaces to stay out of the wasm closure.\nKnown hotspot files:\n{}\n{}",
            LEAK_FRONTIER_FILES.join("\n"),
            render_output(&output)
        );
    }
}

#[test]
#[ignore = "runs native cargo check backstop after wasm cfg changes; invoke through rch"]
fn native_all_targets_backstop_holds() {
    let target_dir = format!("/tmp/asupersync-native-backstop-{}", std::process::id());
    let output = run_cargo_check(&["check", "-p", "asupersync", "--all-targets"], &target_dir);
    assert!(
        output.status.success(),
        "native backstop regressed after wasm cfg changes.\n{}",
        render_output(&output)
    );
}
