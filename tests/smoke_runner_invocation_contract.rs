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
    if output.status.success() {
        return String::from_utf8(output.stdout)
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
            .collect();
    }

    // RCH clean-overlay exports contain exactly the tracked source snapshot but
    // intentionally omit `.git`. Preserve the executable-mode check by reading
    // the exported filesystem metadata instead of treating that absence as a
    // product failure.
    let mut runners = std::fs::read_dir(repo_root().join("scripts"))
        .expect("scripts directory")
        .map(|entry| entry.expect("script directory entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("run_") && name.ends_with("_smoke.sh"))
        })
        .map(|path| {
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                if std::fs::metadata(&path)
                    .expect("smoke runner metadata")
                    .permissions()
                    .mode()
                    & 0o111
                    != 0
                {
                    "100755"
                } else {
                    "100644"
                }
            };
            #[cfg(not(unix))]
            let mode = "100755";
            let relative = path
                .strip_prefix(repo_root())
                .expect("script below repo root")
                .to_string_lossy()
                .replace('\\', "/");
            (mode.to_string(), relative)
        })
        .collect::<Vec<_>>();
    runners.sort();
    runners
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
