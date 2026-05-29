#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const CATALOG_PATH: &str = "artifacts/metamorphic_invariant_catalog_v1.json";
const EXPECTED_VERSION: &str = "metamorphic-invariant-catalog-v1";
const EXPECTED_BEAD: &str = "asupersync-pn8jzv";
const FAMILY_PREFIX: &str = "TransformFamily::";
const EXPECTED_PROOF_TARGET: &str = "--test metamorphic_invariant_catalog_contract";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn catalog() -> Value {
    serde_json::from_str(&read_repo_file(CATALOG_PATH))
        .unwrap_or_else(|err| panic!("parse {CATALOG_PATH}: {err}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn string_vec(value: &Value, key: &str) -> Vec<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn required_families() -> BTreeSet<&'static str> {
    BTreeSet::from([
        "TransformFamily::Backpressure",
        "TransformFamily::CancellationSafety",
        "TransformFamily::Equivalence",
        "TransformFamily::Causality",
        "TransformFamily::Quiescence",
        "TransformFamily::Ordering",
        "TransformFamily::LoserDrain",
        "TransformFamily::Deadline",
        "TransformFamily::Fairness",
        "TransformFamily::ResourceLeak",
        "TransformFamily::Exclusion",
        "TransformFamily::TemporalCoverage",
        "TransformFamily::Replay",
        "TransformFamily::Permutation",
        "TransformFamily::Priority",
        "TransformFamily::CapabilityAttenuation",
        "TransformFamily::Monotonicity",
        "TransformFamily::Reversibility",
    ])
}

#[test]
fn catalog_identity_and_rules_are_pinned() {
    let catalog = catalog();
    assert_eq!(string(&catalog, "contract_version"), EXPECTED_VERSION);
    assert_eq!(string(&catalog, "bead_id"), EXPECTED_BEAD);

    let source = Value::Object(object(&catalog, "source_of_truth").clone());
    assert_eq!(string(&source, "artifact"), CATALOG_PATH);
    assert_eq!(
        string(&source, "contract_test"),
        "tests/metamorphic_invariant_catalog_contract.rs"
    );
    let proof_command = string(&source, "proof_command");
    assert!(
        proof_command.starts_with("rch exec -- env "),
        "proof command must run through rch: {proof_command}"
    );
    assert!(
        proof_command.contains(EXPECTED_PROOF_TARGET),
        "proof command must target this contract: {proof_command}"
    );

    let rules = Value::Object(object(&catalog, "catalog_rules").clone());
    assert_eq!(string(&rules, "transform_family_tag_prefix"), FAMILY_PREFIX);
    assert!(bool_field(&rules, "source_paths_are_repo_relative"));
    assert!(bool_field(&rules, "source_markers_must_exist"));
    assert!(bool_field(&rules, "risk_focus_must_be_nonempty"));
}

#[test]
fn transform_families_are_complete_unique_and_grepable() {
    let catalog = catalog();
    let mut seen = BTreeSet::new();

    for family in array(&catalog, "transform_families") {
        let tag = string(family, "tag");
        assert!(
            tag.starts_with(FAMILY_PREFIX),
            "transform family must be grep-able with {FAMILY_PREFIX}: {tag}"
        );
        assert!(
            tag[FAMILY_PREFIX.len()..]
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric()),
            "family suffix should be stable ASCII identifier text: {tag}"
        );
        assert!(!string(family, "description").is_empty());
        assert!(seen.insert(tag.to_string()), "duplicate family {tag}");
    }

    let expected: BTreeSet<String> = required_families()
        .into_iter()
        .map(str::to_string)
        .collect();
    assert_eq!(seen, expected, "TransformFamily tag set drifted");
}

#[test]
fn invariants_are_source_backed_and_family_covered() {
    let catalog = catalog();
    let family_tags: BTreeSet<String> = array(&catalog, "transform_families")
        .iter()
        .map(|family| string(family, "tag").to_string())
        .collect();

    let mut invariant_ids = BTreeSet::new();
    let mut family_counts: BTreeMap<String, usize> = BTreeMap::new();

    for invariant in array(&catalog, "invariants") {
        let invariant_id = string(invariant, "invariant_id");
        assert!(
            invariant_id.starts_with("metamorphic."),
            "invariant ids must be grep-able and namespaced: {invariant_id}"
        );
        assert!(
            invariant_ids.insert(invariant_id.to_string()),
            "duplicate invariant {invariant_id}"
        );

        let family = string(invariant, "transform_family");
        assert!(
            family_tags.contains(family),
            "{invariant_id} references undefined family {family}"
        );
        *family_counts.entry(family.to_string()).or_insert(0) += 1;

        assert!(!string(invariant, "property").is_empty());
        assert!(!string(invariant, "proof_surface").is_empty());
        assert!(
            !string_vec(invariant, "risk_focus").is_empty(),
            "{invariant_id} must name at least one risk focus"
        );

        let source_paths = string_vec(invariant, "source_paths");
        assert!(
            !source_paths.is_empty(),
            "{invariant_id} must reference source paths"
        );
        let source_texts: Vec<String> = source_paths
            .iter()
            .map(|path| {
                assert!(
                    !path.starts_with('/'),
                    "{invariant_id} path must be repo-relative: {path}"
                );
                assert!(
                    repo_path(path).is_file(),
                    "{invariant_id} missing source path {path}"
                );
                read_repo_file(path)
            })
            .collect();

        for marker in string_vec(invariant, "relation_markers") {
            assert!(
                source_texts.iter().any(|source| source.contains(&marker)),
                "{invariant_id} marker {marker:?} was not found in any source path"
            );
        }
    }

    assert_eq!(
        invariant_ids.len(),
        family_tags.len(),
        "this catalog pins exactly one representative invariant per TransformFamily"
    );
    for family in family_tags {
        assert_eq!(
            family_counts.get(&family).copied().unwrap_or_default(),
            1,
            "{family} should have one representative invariant"
        );
    }
}

#[test]
fn critical_runtime_relations_are_cataloged() {
    let catalog = catalog();
    let ids: BTreeSet<String> = array(&catalog, "invariants")
        .iter()
        .map(|invariant| string(invariant, "invariant_id").to_string())
        .collect();

    for required in [
        "metamorphic.channel.mpsc.two_phase_cancel",
        "metamorphic.region.close.blocks_until_children_complete",
        "metamorphic.combinator.race.loser_drain",
        "metamorphic.trace.dpor.equivalent_schedule_dedup",
        "metamorphic.scheduler.three_lane.priority_ratios",
        "metamorphic.cx.scope.monotonic_attenuation",
    ] {
        assert!(
            ids.contains(required),
            "missing critical relation {required}"
        );
    }
}
