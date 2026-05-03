//! Contract tests for direct smoke-runner operator invocation.

#![allow(missing_docs)]

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn tracked_smoke_runners() -> Vec<(String, String)> {
    let output = Command::new("git")
        .current_dir(repo_root())
        .args(["ls-files", "-s", "scripts/run_*_smoke.sh"])
        .output()
        .expect("git ls-files should run");
    assert!(
        output.status.success(),
        "git ls-files failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout)
        .expect("git output should be utf8")
        .lines()
        .map(|line| {
            let mut parts = line.split_whitespace();
            let mode = parts.next().expect("mode").to_string();
            let _object = parts.next().expect("object");
            let _stage = parts.next().expect("stage");
            let path = parts.next().expect("path").to_string();
            (mode, path)
        })
        .collect()
}

#[test]
fn tracked_smoke_runners_have_executable_mode_and_shebang() {
    let runners = tracked_smoke_runners();
    assert!(!runners.is_empty(), "expected tracked smoke runners");

    let mut failures = Vec::new();
    for (mode, path) in runners {
        if mode != "100755" {
            failures.push(format!("{path}: expected git mode 100755, got {mode}"));
        }

        let first_line = std::fs::read_to_string(repo_root().join(&path))
            .unwrap_or_else(|err| panic!("failed to read {path}: {err}"))
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        if first_line != "#!/usr/bin/env bash" {
            failures.push(format!("{path}: invalid shebang {first_line:?}"));
        }
    }

    assert!(
        failures.is_empty(),
        "smoke runner mode/shebang failures:\n{}",
        failures.join("\n")
    );
}

#[test]
fn tracked_smoke_runners_support_direct_and_bash_list() {
    let runners = tracked_smoke_runners();
    let mut failures = Vec::new();

    for (_mode, path) in runners {
        let direct = Command::new(repo_root().join(&path))
            .current_dir(repo_root())
            .arg("--list")
            .output()
            .unwrap_or_else(|err| panic!("failed to run direct {path} --list: {err}"));
        if !direct.status.success() {
            failures.push(format!(
                "{path}: direct --list failed rc={:?} stderr={}",
                direct.status.code(),
                String::from_utf8_lossy(&direct.stderr)
            ));
        }

        let bash = Command::new("bash")
            .current_dir(repo_root())
            .args([path.as_str(), "--list"])
            .output()
            .unwrap_or_else(|err| panic!("failed to run bash {path} --list: {err}"));
        if !bash.status.success() {
            failures.push(format!(
                "{path}: bash --list failed rc={:?} stderr={}",
                bash.status.code(),
                String::from_utf8_lossy(&bash.stderr)
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "smoke runner --list failures:\n{}",
        failures.join("\n")
    );
}
