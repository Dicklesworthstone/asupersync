use std::collections::BTreeMap;
use std::fs;

const CARGO_TOML: &str = "Cargo.toml";
const README: &str = "README.md";
const AGENTS: &str = "AGENTS.md";

fn feature_arrays(manifest: &str) -> BTreeMap<String, Vec<String>> {
    let mut in_features = false;
    let mut rows = BTreeMap::new();

    for raw_line in manifest.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') {
            in_features = line == "[features]";
            continue;
        }
        if !in_features || line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, raw_values)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_string();
        let raw_values = raw_values.trim();
        if !raw_values.starts_with('[') || !raw_values.ends_with(']') {
            continue;
        }

        let values = raw_values
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split(',')
            .filter_map(|value| {
                let value = value.trim().trim_matches('"');
                (!value.is_empty()).then(|| value.to_string())
            })
            .collect::<Vec<_>>();
        rows.insert(key, values);
    }

    rows
}

#[test]
fn default_features_do_not_enable_test_internals_for_downstream_consumers() {
    let manifest = fs::read_to_string(CARGO_TOML).expect("read Cargo.toml");
    let features = feature_arrays(&manifest);
    let default = features.get("default").expect("default feature row");

    assert_eq!(
        default,
        &vec!["proc-macros".to_string(), "nightly-outcome-try".to_string()],
        "default features must stay production-safe; test-internals is opt-in"
    );
    assert!(
        !default.iter().any(|feature| feature == "test-internals"),
        "test-internals must never be in the default feature set"
    );
    assert!(
        features
            .get("test-internals")
            .expect("test-internals feature row")
            .iter()
            .any(|feature| feature == "dep:visibility"),
        "test-internals should remain the explicit gate for visibility widening"
    );
}

#[test]
fn docs_match_default_feature_policy() {
    let readme = fs::read_to_string(README).expect("read README.md");
    let agents = fs::read_to_string(AGENTS).expect("read AGENTS.md");

    assert!(
        readme
            .contains("| `test-internals` | Expose test-only helpers (not for production) | No |"),
        "README feature table must document test-internals as non-default"
    );
    assert!(
        readme.contains("default production\nfeature set is intentionally limited")
            && readme.contains("`proc-macros` plus\n`nightly-outcome-try`"),
        "README must explain the production default feature boundary"
    );
    assert!(
        agents.contains("default = [\"proc-macros\", \"nightly-outcome-try\"]"),
        "AGENTS feature summary must not put test-internals in default"
    );
}
