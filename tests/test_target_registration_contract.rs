//! Feature-gated integration tests are registered with their features
//! (asupersync-bi2462.87).
//!
//! A top-level `tests/*.rs` file whose crate-level `#![cfg(...)]` needs a
//! non-default feature compiles to an empty crate under default features, and
//! `cargo test` reports it as passing. A `[[test]]` entry with
//! `required-features` makes cargo skip it explicitly and refuse
//! `--test <name>` without the features. The cfg reading is the main
//! watchdog's (`scripts/main_watchdog.py registration`), so the repository has
//! one evaluator of these gates.

use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;

fn census(root: &Path) -> Value {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new("python3")
        .arg(manifest_dir.join("scripts/main_watchdog.py"))
        .arg("registration")
        .arg("--root")
        .arg(root)
        .output()
        .expect("python3 runs the watchdog registration census");
    assert!(
        output.status.success(),
        "registration census failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("registration census prints JSON")
}

#[test]
fn every_feature_gated_integration_test_is_registered_with_its_features() {
    let report = census(Path::new(env!("CARGO_MANIFEST_DIR")));
    assert_eq!(
        report["unregistered"],
        json!([]),
        "register each file in Cargo.toml with `required-features`: {report:#}"
    );
    assert_eq!(
        report["missing_features"],
        json!([]),
        "a registered entry lacks a feature its gate needs, so default builds compile it empty: {report:#}"
    );
}

fn planted_root() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "asupersync-registration-census-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(root.join("tests")).expect("create planted tests directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"planted\"\nversion = \"0.0.0\"\n\n\
         [features]\ndefault = [\"base\"]\nbase = []\ntls = []\nextra = []\n\n\
         [[test]]\nname = \"under\"\npath = \"tests/under.rs\"\nrequired-features = [\"tls\"]\n\n\
         [[test]]\nname = \"complete\"\npath = \"tests/complete.rs\"\nrequired-features = [\"tls\", \"extra\"]\n",
    )
    .expect("write planted manifest");
    for (name, source) in [
        ("plain.rs", "// no crate cfg\n"),
        ("default_only.rs", "#![cfg(feature = \"base\")]\n"),
        ("planted.rs", "#![cfg(feature = \"tls\")]\n"),
        ("under.rs", "#![cfg(all(feature = \"tls\", feature = \"extra\"))]\n"),
        ("complete.rs", "#![cfg(all(feature = \"tls\", feature = \"extra\"))]\n"),
        ("either.rs", "#![cfg(any(feature = \"tls\", feature = \"extra\"))]\n"),
    ] {
        std::fs::write(root.join("tests").join(name), source).expect("write planted test file");
    }
    root
}

/// Negative control: an unregistered gated file and an entry missing one of
/// its features are both reported. A default-only gate and a complete entry
/// are not, and an `any(...)` gate is exempt rather than silently accepted.
#[test]
fn the_census_reports_an_unregistered_and_an_underregistered_file() {
    let report = census(&planted_root());
    assert_eq!(
        report["unregistered"],
        json!([{"path": "tests/planted.rs", "features": ["tls"]}]),
        "{report:#}"
    );
    assert_eq!(
        report["missing_features"],
        json!([{"path": "tests/under.rs", "features": ["extra"]}]),
        "{report:#}"
    );
    assert_eq!(
        report["exempt"],
        json!([{"path": "tests/either.rs", "reason": "alternative feature sets (any): not expressible"}]),
        "{report:#}"
    );
}
