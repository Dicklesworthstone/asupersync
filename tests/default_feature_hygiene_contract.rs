use std::collections::BTreeMap;
use std::fs;

const CARGO_TOML: &str = "Cargo.toml";
const README: &str = "README.md";
const AGENTS: &str = "AGENTS.md";

fn feature_arrays(manifest: &str) -> BTreeMap<String, Vec<String>> {
    let mut in_features = false;
    let mut rows = BTreeMap::new();
    let mut statement = String::new();

    for raw_line in manifest.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') {
            in_features = line == "[features]";
            statement.clear();
            continue;
        }
        if !in_features || line.is_empty() || line.starts_with('#') {
            continue;
        }

        if !statement.is_empty() {
            statement.push(' ');
        }
        statement.push_str(line);
        if !statement.contains('=') || !statement.trim_end().ends_with(']') {
            continue;
        }

        let Some((key, raw_values)) = statement.split_once('=') else {
            statement.clear();
            continue;
        };
        let key = key.trim().to_string();
        let raw_values = raw_values.trim();
        if !raw_values.starts_with('[') || !raw_values.ends_with(']') {
            statement.clear();
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
        statement.clear();
    }

    rows
}

#[test]
fn default_features_do_not_enable_test_internals_for_downstream_consumers() {
    let manifest = fs::read_to_string(CARGO_TOML).expect("read Cargo.toml");
    let features = feature_arrays(&manifest);
    let default = features.get("default").expect("default feature row");

    // `runtime-core` and `native-runtime` are empty compatibility markers for the
    // planned runtime module split (0967799e0). They are default so that default
    // builds keep those modules once the split gates them (asupersync-bi2462.138).
    assert_eq!(
        default,
        &vec![
            "proc-macros".to_string(),
            "nightly-outcome-try".to_string(),
            "runtime-core".to_string(),
            "native-runtime".to_string(),
        ],
        "default features must stay production-safe; test-internals is opt-in"
    );
    for marker in ["runtime-core", "native-runtime"] {
        assert!(
            features.get(marker).is_some_and(Vec::is_empty),
            "default compatibility marker `{marker}` must stay empty until its module gate exists"
        );
    }
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
            && readme.contains("`proc-macros` plus\n`nightly-outcome-try`")
            && readme.contains("`runtime-core` and\n`native-runtime`"),
        "README must explain the production default feature boundary"
    );
    assert!(
        agents.contains(
            "default = [\"proc-macros\", \"nightly-outcome-try\", \"runtime-core\", \"native-runtime\"]"
        ),
        "AGENTS feature summary must match the manifest default and not put test-internals in default"
    );
}
