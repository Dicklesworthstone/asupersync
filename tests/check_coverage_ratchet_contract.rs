#![allow(missing_docs)]

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

const SCRIPT_PATH: &str = "scripts/check_coverage_ratchet.py";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn hidden_repo_paths_do_not_match_non_hidden_prefixes() {
    let snippet = r#"
import importlib.util
import json
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "check_coverage_ratchet",
    "scripts/check_coverage_ratchet.py",
)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
repo_root = Path.cwd()

print(json.dumps({
    "hidden_normalized": module.normalize_path(".beads/issues.jsonl", repo_root),
    "leading_segment_normalized": module.normalize_path("./.beads/issues.jsonl", repo_root),
    "absolute_hidden_normalized": module.normalize_path(
        str(repo_root / ".beads/issues.jsonl"),
        repo_root,
    ),
    "matches_hidden_prefix": module.starts_with_any(".beads/issues.jsonl", [".beads/"]),
    "matches_leading_segment_hidden_prefix": module.starts_with_any(
        ".beads/issues.jsonl",
        ["./.beads/"],
    ),
    "matches_non_hidden_prefix": module.starts_with_any(".beads/issues.jsonl", ["beads/"]),
}, sort_keys=True))
"#;
    let output = Command::new("python3")
        .arg("-c")
        .arg(snippet)
        .current_dir(repo_root())
        .output()
        .expect("run coverage ratchet normalization snippet");
    assert!(
        output.status.success(),
        "normalization snippet failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value =
        serde_json::from_slice(&output.stdout).expect("normalization output must be JSON");
    assert_eq!(
        parsed["hidden_normalized"].as_str(),
        Some(".beads/issues.jsonl")
    );
    assert_eq!(
        parsed["leading_segment_normalized"].as_str(),
        Some(".beads/issues.jsonl")
    );
    assert_eq!(
        parsed["absolute_hidden_normalized"].as_str(),
        Some(".beads/issues.jsonl")
    );
    assert_eq!(parsed["matches_hidden_prefix"].as_bool(), Some(true));
    assert_eq!(
        parsed["matches_leading_segment_hidden_prefix"].as_bool(),
        Some(true)
    );
    assert_eq!(parsed["matches_non_hidden_prefix"].as_bool(), Some(false));
}

#[test]
fn script_help_is_available() {
    let output = Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--help")
        .current_dir(repo_root())
        .output()
        .expect("run coverage ratchet helper --help");
    assert!(
        output.status.success(),
        "--help should succeed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
