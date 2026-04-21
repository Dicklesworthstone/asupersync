#![allow(clippy::all)]
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
