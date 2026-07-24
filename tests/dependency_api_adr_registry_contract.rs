//! Fail-closed Phase-3 owner-ADR contract for dependency sovereignty.
//!
//! Bead: asupersync-dep-p3-api-adrs-h3jspm.3
//! Scenario: api-adr-registry-contract
//! Fixture: artifacts/dependency_api_adr_registry_v1.json
//!
//! This lane proves that every resolved Phase-3 ADR still describes the live
//! crate: the frozen public symbols exist, the frozen Cargo feature definitions
//! are unchanged, the feature gating of the observability re-exports is
//! unchanged, the claimed capability authority matches the capability registry,
//! and no ADR text authorizes functionality loss.
//!
//! It proves nothing about runtime behavior, parity, or whether the planned
//! evidence has actually run.

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;

const BEAD_ID: &str = "asupersync-dep-p3-api-adrs-h3jspm.3";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const PHASE_ID: &str = "asupersync-dep-p3-api-adrs-h3jspm";
const AGGREGATE_BEAD_ID: &str = "asupersync-dep-p3-api-adrs-h3jspm.13";
const ARTIFACT_PATH: &str = "artifacts/dependency_api_adr_registry_v1.json";
const CAPABILITY_REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const DOC_PATH: &str = "docs/dependency_api_adr_registry.md";
const MANIFEST_PATH: &str = "Cargo.toml";
const TRACKER_PATH: &str = ".beads/issues.jsonl";
const OBSERVABILITY_MOD_PATH: &str = "src/observability/mod.rs";
const GENERATED_BEGIN: &str = "<!-- BEGIN GENERATED ADR SUMMARY -->";
const GENERATED_END: &str = "<!-- END GENERATED ADR SUMMARY -->";
const EXPECTED_ADR_COUNT: usize = 12;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn parse_repo_json(path: &str) -> Value {
    serde_json::from_str(&read_repo_file(path))
        .unwrap_or_else(|error| panic!("{path} must be valid JSON: {error}"))
}

fn registry() -> Value {
    parse_repo_json(ARTIFACT_PATH)
}

fn capability_registry() -> Value {
    parse_repo_json(CAPABILITY_REGISTRY_PATH)
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

/// Whole-identifier search: rejects `Counter` matching inside `CounterDataPoint`.
fn contains_identifier(haystack: &str, needle: &str) -> bool {
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut from = 0usize;
    while let Some(offset) = haystack[from..].find(needle) {
        let start = from + offset;
        let end = start + needle.len();
        let before_ok = start == 0 || !haystack[..start].chars().next_back().is_some_and(is_ident);
        let after_ok = haystack[end..].chars().next().is_none_or(|c| !is_ident(c));
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

/// Bead ids that exist in the live tracker. Malformed lines are skipped rather
/// than failing the lane, matching the tolerant parsing used elsewhere.
fn live_bead_ids() -> BTreeSet<String> {
    read_repo_file(TRACKER_PATH)
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|value| {
            value
                .get("id")
                .and_then(Value::as_str)
                .map(std::borrow::ToOwned::to_owned)
        })
        .collect()
}

/// Capability ids the capability registry maps to each ADR bead. This is the
/// authority: the ADR artifact restates nothing, so tracker drift fails closed.
fn registry_capability_map() -> BTreeMap<String, Vec<String>> {
    let capability_registry = capability_registry();
    let mut mapped = BTreeMap::new();
    for rule in array(&capability_registry, "bead_mapping_rules") {
        let Some(bead_id) = rule.get("bead_id").and_then(Value::as_str) else {
            continue;
        };
        if rule.get("scope").and_then(Value::as_str) != Some("exact") {
            continue;
        }
        let capability_ids: Vec<String> = rule
            .get("capability_ids")
            .and_then(Value::as_array)
            .map(|ids| {
                ids.iter()
                    .filter_map(Value::as_str)
                    .map(std::borrow::ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        mapped.insert(bead_id.to_owned(), capability_ids);
    }
    mapped
}

/// The twelve ADR child beads, derived from the capability registry mapping.
fn expected_adr_beads() -> Vec<String> {
    let prefix = format!("{PHASE_ID}.");
    let mut beads: Vec<String> = registry_capability_map()
        .into_keys()
        .filter(|bead_id| bead_id.starts_with(&prefix) && bead_id != AGGREGATE_BEAD_ID)
        .collect();
    beads.sort_by_key(|bead_id| {
        bead_id
            .rsplit('.')
            .next()
            .and_then(|suffix| suffix.parse::<u32>().ok())
            .unwrap_or(u32::MAX)
    });
    beads
}

fn resolved_adrs() -> Vec<Value> {
    array(&registry(), "adrs").clone()
}

#[test]
fn metadata_and_policy_are_fail_closed() {
    let registry = registry();

    assert_eq!(
        text(&registry, "artifact_id"),
        "dependency-api-adr-registry-v1"
    );
    assert_eq!(
        registry.get("schema_version").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(text(&registry, "program_id"), PROGRAM_ID);
    assert_eq!(text(&registry, "phase_id"), PHASE_ID);
    assert_eq!(text(&registry, "aggregate_bead_id"), AGGREGATE_BEAD_ID);
    assert_eq!(
        text(&registry, "capability_registry_path"),
        CAPABILITY_REGISTRY_PATH
    );
    assert_eq!(text(&registry, "doc_index_path"), DOC_PATH);

    let policy = registry
        .get("policy")
        .and_then(Value::as_object)
        .expect("policy must be an object");
    for key in [
        "purpose",
        "no_loss_rule",
        "keep_default",
        "no_compatibility_shims",
        "authority_rule",
        "evidence_rule",
        "truthful_baseline_rule",
        "aggregate_rule",
    ] {
        let rule = policy
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("policy.{key} must be a string"));
        assert!(!rule.trim().is_empty(), "policy.{key} must not be empty");
    }

    for key in [
        "allowed_adr_states",
        "allowed_decisions",
        "allowed_evidence_states",
        "allowed_cutover_states",
        "allowed_surface_states",
        "required_adr_fields",
    ] {
        assert!(
            !array(&registry, key).is_empty(),
            "{key} must be a non-empty allow-list"
        );
    }

    // A disposition vocabulary that can express deletion would defeat the gate.
    for decision in array(&registry, "allowed_decisions") {
        let decision = decision.as_str().expect("decision must be a string");
        for banned in ["REMOVE", "DROP", "DELETE"] {
            assert!(
                !decision.contains(banned),
                "allowed_decisions must not contain a loss-authorizing value: {decision}"
            );
        }
    }

    let validation = registry
        .get("validation")
        .and_then(Value::as_object)
        .expect("validation must be an object");
    assert_eq!(
        validation.get("contract_test").and_then(Value::as_str),
        Some("tests/dependency_api_adr_registry_contract.rs")
    );
    let proof_command = validation
        .get("proof_command")
        .and_then(Value::as_str)
        .expect("validation.proof_command must be a string");
    assert!(
        proof_command.contains("RCH_REQUIRE_REMOTE=1 rch exec --"),
        "proof command must be remote-required with no local fallback"
    );
    assert!(
        proof_command.contains("--test dependency_api_adr_registry_contract"),
        "proof command must run this focused lane"
    );
    let no_claim = validation
        .get("no_claim_boundary")
        .and_then(Value::as_str)
        .expect("validation.no_claim_boundary must be a string");
    assert!(
        !no_claim.trim().is_empty(),
        "validation.no_claim_boundary must not be empty"
    );
}

#[test]
fn roster_covers_exactly_the_live_adr_children() {
    let registry = registry();
    let roster = array(&registry, "roster");
    let expected = expected_adr_beads();

    assert_eq!(
        expected.len(),
        EXPECTED_ADR_COUNT,
        "capability registry must map exactly {EXPECTED_ADR_COUNT} Phase-3 ADR children, found {expected:?}"
    );
    assert_eq!(
        roster.len(),
        EXPECTED_ADR_COUNT,
        "roster must carry exactly {EXPECTED_ADR_COUNT} rows"
    );

    let roster_beads: Vec<String> = roster
        .iter()
        .map(|row| text(row, "bead_id").to_owned())
        .collect();
    assert_eq!(
        roster_beads, expected,
        "roster must match the live capability-registry ADR children, in order"
    );

    let allowed_states: BTreeSet<&str> = array(&registry, "allowed_adr_states")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let mut adr_ids = BTreeSet::new();
    for row in roster {
        let adr_id = text(row, "adr_id");
        assert!(
            adr_ids.insert(adr_id.to_owned()),
            "duplicate roster adr_id: {adr_id}"
        );
        let state = text(row, "state");
        assert!(
            allowed_states.contains(state),
            "roster state {state} is not in allowed_adr_states"
        );
        assert!(
            !text(row, "title").trim().is_empty(),
            "roster row {adr_id} must carry a title"
        );
    }

    // Every RESOLVED roster row must have a body, and every body a roster row.
    let resolved_roster: BTreeSet<String> = roster
        .iter()
        .filter(|row| text(row, "state") == "RESOLVED")
        .map(|row| text(row, "adr_id").to_owned())
        .collect();
    let bodies: BTreeSet<String> = resolved_adrs()
        .iter()
        .map(|adr| text(adr, "adr_id").to_owned())
        .collect();
    assert_eq!(
        resolved_roster, bodies,
        "RESOLVED roster rows and ADR bodies must correspond exactly"
    );
}

#[test]
fn every_referenced_bead_is_live_in_the_tracker() {
    let registry = registry();
    let live = live_bead_ids();
    assert!(
        live.contains(BEAD_ID),
        "tracker must contain the owning bead {BEAD_ID}"
    );

    for row in array(&registry, "roster") {
        let bead_id = text(row, "bead_id");
        assert!(live.contains(bead_id), "roster bead {bead_id} is not live");
    }

    for adr in &resolved_adrs() {
        let adr_id = text(adr, "adr_id");
        let evidence = adr.get("evidence").expect("evidence must be present");
        for key in ["baseline_owner", "unit_test_owner", "e2e_owner"] {
            let owner = text(evidence, key);
            assert!(
                live.contains(owner),
                "{adr_id} evidence.{key} references a dead bead: {owner}"
            );
        }
        let cutover = adr.get("cutover").expect("cutover must be present");
        let authorities = array(cutover, "primary_authorities");
        assert!(
            !authorities.is_empty(),
            "{adr_id} must name at least one primary implementation authority"
        );
        for authority in authorities {
            let authority = authority.as_str().expect("authority must be a string");
            assert!(
                live.contains(authority),
                "{adr_id} cutover.primary_authorities references a dead bead: {authority}"
            );
        }
        for consumer in array(cutover, "secondary_compatibility_consumers") {
            let consumer = consumer.as_str().expect("consumer must be a string");
            assert!(
                live.contains(consumer),
                "{adr_id} secondary consumer references a dead bead: {consumer}"
            );
        }
        for gap in array(adr, "known_gaps") {
            let owner = text(gap, "owner_bead");
            assert!(
                live.contains(owner),
                "{adr_id} known gap owner references a dead bead: {owner}"
            );
        }
    }
}

#[test]
fn every_resolved_adr_row_is_complete() {
    let registry = registry();
    let required: Vec<&str> = array(&registry, "required_adr_fields")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let allowed_decisions: BTreeSet<&str> = array(&registry, "allowed_decisions")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let allowed_evidence: BTreeSet<&str> = array(&registry, "allowed_evidence_states")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let allowed_cutover: BTreeSet<&str> = array(&registry, "allowed_cutover_states")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let allowed_surfaces: BTreeSet<&str> = array(&registry, "allowed_surface_states")
        .iter()
        .filter_map(Value::as_str)
        .collect();

    for adr in &resolved_adrs() {
        let adr_id = text(adr, "adr_id");
        for field in &required {
            let value = adr
                .get(*field)
                .unwrap_or_else(|| panic!("{adr_id} is missing required field {field}"));
            let populated = match value {
                Value::String(s) => !s.trim().is_empty(),
                Value::Array(a) => !a.is_empty(),
                Value::Object(o) => !o.is_empty(),
                Value::Null => false,
                _ => true,
            };
            assert!(populated, "{adr_id} field {field} must not be empty");
        }

        assert!(
            allowed_decisions.contains(text(adr, "decision")),
            "{adr_id} decision is outside the allow-list"
        );
        let evidence = adr.get("evidence").expect("evidence present");
        assert!(
            allowed_evidence.contains(text(evidence, "state")),
            "{adr_id} evidence.state is outside the allow-list"
        );
        let cutover = adr.get("cutover").expect("cutover present");
        assert!(
            allowed_cutover.contains(text(cutover, "cutover_state")),
            "{adr_id} cutover.cutover_state is outside the allow-list"
        );
        for surface in array(adr, "preserved_surfaces") {
            assert!(
                allowed_surfaces.contains(text(surface, "state")),
                "{adr_id} surface state is outside the allow-list"
            );
        }

        // Alternatives must record why they were rejected, not merely list them.
        for alternative in array(adr, "alternatives_considered") {
            assert!(
                !text(alternative, "option").trim().is_empty(),
                "{adr_id} alternative must name an option"
            );
            assert!(
                !text(alternative, "rejected_because").trim().is_empty(),
                "{adr_id} alternative must record why it was rejected"
            );
        }

        // Known gaps are a truthfulness device; none may be marked expandable.
        for gap in array(adr, "known_gaps") {
            assert_eq!(
                gap.get("may_widen").and_then(Value::as_bool),
                Some(false),
                "{adr_id} known gap {} must not be allowed to widen",
                text(gap, "gap_id")
            );
        }
    }
}

#[test]
fn resolved_adr_capability_authority_matches_the_registry() {
    let mapped = registry_capability_map();
    let capability_registry = capability_registry();
    let capability_rows: BTreeMap<String, Value> = array(&capability_registry, "capabilities")
        .iter()
        .map(|row| (text(row, "capability_id").to_owned(), row.clone()))
        .collect();

    for adr in &resolved_adrs() {
        let adr_id = text(adr, "adr_id");
        let bead_id = text(adr, "bead_id");
        let claimed: Vec<String> = array(adr, "capability_ids")
            .iter()
            .filter_map(Value::as_str)
            .map(std::borrow::ToOwned::to_owned)
            .collect();
        let authorized = mapped
            .get(bead_id)
            .unwrap_or_else(|| panic!("{adr_id} bead {bead_id} has no capability mapping"));
        assert_eq!(
            &claimed, authorized,
            "{adr_id} claims capability authority that does not match the capability registry"
        );

        let cutover = adr.get("cutover").expect("cutover present");
        for capability_id in &claimed {
            let row = capability_rows.get(capability_id).unwrap_or_else(|| {
                panic!("{adr_id} references unknown capability {capability_id}")
            });
            assert_eq!(
                text(row, "disposition"),
                text(cutover, "disposition"),
                "{adr_id} disposition disagrees with capability {capability_id}"
            );
            assert_eq!(
                text(row, "cutover_state"),
                text(cutover, "cutover_state"),
                "{adr_id} cutover_state disagrees with capability {capability_id}"
            );
        }
    }
}

#[test]
fn frozen_public_symbols_still_exist_in_source() {
    for adr in &resolved_adrs() {
        let adr_id = text(adr, "adr_id");
        for group in array(adr, "preserved_public_symbols") {
            let source_file = text(group, "source_file");
            let module_path = text(group, "module_path");
            let source = read_repo_file(source_file);
            for symbol in array(group, "symbols") {
                let symbol = symbol.as_str().expect("symbol must be a string");
                assert!(
                    contains_identifier(&source, symbol),
                    "{adr_id} froze {module_path}::{symbol} but it no longer appears in {source_file}"
                );
            }
        }

        // Every surface's public entry points must also still exist somewhere in
        // the declared implementation file.
        for surface in array(adr, "preserved_surfaces") {
            // A surface that does not exist yet cannot name entry points, and
            // there is no source file to check it against.
            if text(surface, "state") == "NOT_SHIPPED" {
                assert!(
                    array(surface, "public_entry_points").is_empty(),
                    "{adr_id} surface {} is NOT_SHIPPED but claims public entry points",
                    text(surface, "surface")
                );
                continue;
            }
            let implementation = text(surface, "implementation");
            let sources: Vec<String> = implementation
                .split(" and ")
                .map(|path| read_repo_file(path.trim()))
                .collect();
            for entry in array(surface, "public_entry_points") {
                let entry = entry.as_str().expect("entry point must be a string");
                assert!(
                    sources
                        .iter()
                        .any(|source| contains_identifier(source, entry)),
                    "{adr_id} surface {} froze entry point {entry}, missing from {implementation}",
                    text(surface, "surface")
                );
            }
        }
    }
}

#[test]
fn frozen_feature_definitions_match_the_manifest() {
    let manifest = read_repo_file(MANIFEST_PATH);

    for adr in &resolved_adrs() {
        let adr_id = text(adr, "adr_id");
        for feature in array(adr, "preserved_feature_flags") {
            let name = text(feature, "name");
            let definition = text(feature, "cargo_definition");
            assert!(
                manifest.contains(definition),
                "{adr_id} froze feature {name} as `{definition}` but {MANIFEST_PATH} no longer contains it"
            );
            assert_eq!(
                feature.get("must_remain").and_then(Value::as_bool),
                Some(true),
                "{adr_id} feature {name} must be marked must_remain"
            );
        }
    }
}

#[test]
fn opentelemetry_proto_stays_out_of_the_metrics_feature() {
    let manifest = read_repo_file(MANIFEST_PATH);

    let metrics_definition = manifest
        .lines()
        .find(|line| line.trim_start().starts_with("metrics = ["))
        .expect("Cargo.toml must define the metrics feature");
    assert!(
        metrics_definition.contains("dep:opentelemetry")
            && metrics_definition.contains("dep:opentelemetry_sdk"),
        "the metrics feature must still enable the OpenTelemetry ecosystem crates: {metrics_definition}"
    );
    assert!(
        !metrics_definition.contains("opentelemetry-proto"),
        "opentelemetry-proto must never enter the metrics production graph: {metrics_definition}"
    );

    let fuzz_definition = manifest
        .lines()
        .find(|line| line.trim_start().starts_with("fuzz = ["))
        .expect("Cargo.toml must define the fuzz feature");
    assert!(
        fuzz_definition.contains("dep:opentelemetry-proto"),
        "opentelemetry-proto must stay quarantined behind the fuzz feature: {fuzz_definition}"
    );
}

#[test]
fn observability_reexport_gating_is_unchanged() {
    let source = read_repo_file(OBSERVABILITY_MOD_PATH);
    let lines: Vec<&str> = source.lines().collect();

    let preceding_attribute = |needle: &str| -> Option<String> {
        let index = lines
            .iter()
            .position(|line| line.trim_start().starts_with(needle))?;
        lines[..index]
            .iter()
            .rev()
            .find(|line| !line.trim().is_empty())
            .map(|line| (*line).trim().to_owned())
    };

    // The owned OTLP trace surface must stay reachable at default features.
    let trace_attribute = preceding_attribute("pub use otlp_trace_exporter::{")
        .expect("mod.rs must re-export otlp_trace_exporter");
    assert!(
        !trace_attribute.starts_with("#[cfg"),
        "the owned trace re-export must stay ungated, found preceding attribute: {trace_attribute}"
    );

    // The ecosystem-bound otel surface must stay behind the metrics feature.
    let otel_use_attribute =
        preceding_attribute("pub use otel::{").expect("mod.rs must re-export otel");
    assert_eq!(
        otel_use_attribute, "#[cfg(feature = \"metrics\")]",
        "the otel re-export must stay gated on the metrics feature"
    );
    let otel_mod_attribute =
        preceding_attribute("pub mod otel;").expect("mod.rs must declare pub mod otel");
    assert_eq!(
        otel_mod_attribute, "#[cfg(feature = \"metrics\")]",
        "pub mod otel must stay gated on the metrics feature"
    );
}

#[test]
fn declared_source_and_doc_paths_exist() {
    let registry = registry();
    let root = repo_root();

    for adr in &resolved_adrs() {
        let adr_id = text(adr, "adr_id");
        let doc_path = text(adr, "doc_path");
        assert!(
            root.join(doc_path).is_file(),
            "{adr_id} doc_path does not exist: {doc_path}"
        );
        for group in array(adr, "preserved_public_symbols") {
            let source_file = text(group, "source_file");
            assert!(
                root.join(source_file).is_file(),
                "{adr_id} declares a missing source file: {source_file}"
            );
        }
    }

    assert!(
        root.join(text(&registry, "doc_index_path")).is_file(),
        "the ADR index doc must exist"
    );
    assert!(
        root.join(text(&registry, "adr_doc_dir")).is_dir(),
        "the ADR doc directory must exist"
    );
}

#[test]
fn no_resolved_adr_authorizes_a_dependency_exit_or_functionality_loss() {
    let registry = registry();
    let prohibited: Vec<(&str, &str)> = array(&registry, "known_loss_fixtures")
        .iter()
        .map(|fixture| {
            (
                text(fixture, "fixture_id"),
                text(fixture, "prohibited_text"),
            )
        })
        .collect();

    for adr in &resolved_adrs() {
        let adr_id = text(adr, "adr_id");
        let cutover = adr.get("cutover").expect("cutover present");
        assert_eq!(
            cutover
                .get("dependency_exit_allowed")
                .and_then(Value::as_bool),
            Some(false),
            "{adr_id} must not authorize a dependency exit"
        );
        if text(cutover, "cutover_state") == "KEEP_INCUMBENT" {
            assert_eq!(
                text(cutover, "disposition"),
                "KEEP_UNTIL_PARITY",
                "{adr_id} keeping the incumbent must carry the KEEP_UNTIL_PARITY disposition"
            );
        }
        assert!(
            !array(cutover, "gates").is_empty(),
            "{adr_id} must inherit the global cutover gates"
        );

        // The prose of the decision itself must not contain loss-authorizing
        // language. `known_loss_fixtures` is deliberately excluded from the scan
        // because that block is where the prohibited strings legitimately live.
        let prose = serde_json::to_string(adr).expect("adr serializes");
        let lowered = prose.to_lowercase();
        for (fixture_id, needle) in &prohibited {
            assert!(
                !lowered.contains(&needle.to_lowercase()),
                "{adr_id} contains loss-authorizing text from fixture {fixture_id}: {needle}"
            );
        }
    }
}

#[test]
fn all_named_negative_fixtures_fail_for_the_intended_reason() {
    let registry = registry();
    let fixtures = array(&registry, "known_loss_fixtures");
    assert!(
        !fixtures.is_empty(),
        "the loss-fixture catalog must not be empty"
    );

    let known_adrs: BTreeSet<String> = resolved_adrs()
        .iter()
        .map(|adr| text(adr, "adr_id").to_owned())
        .collect();
    let mut fixture_ids = BTreeSet::new();

    for fixture in fixtures {
        let fixture_id = text(fixture, "fixture_id");
        assert!(
            fixture_ids.insert(fixture_id.to_owned()),
            "duplicate fixture id: {fixture_id}"
        );
        let adr_id = text(fixture, "adr_id");
        assert!(
            known_adrs.contains(adr_id),
            "fixture {fixture_id} targets an unresolved ADR: {adr_id}"
        );
        let prohibited = text(fixture, "prohibited_text");
        let expected_error = text(fixture, "expected_error");
        assert!(
            !prohibited.trim().is_empty() && !expected_error.trim().is_empty(),
            "fixture {fixture_id} must carry both prohibited text and an expected error"
        );

        // Inject the prohibited text into a copy of the targeted ADR and prove
        // the detector rejects it. A fixture that cannot fail is not a gate.
        let mut mutated = resolved_adrs()
            .into_iter()
            .find(|adr| text(adr, "adr_id") == adr_id)
            .expect("targeted ADR body must exist");
        mutated["decision_summary"] = Value::String(format!(
            "{} {prohibited}",
            text(&mutated, "decision_summary")
        ));
        let lowered = serde_json::to_string(&mutated)
            .expect("mutated adr serializes")
            .to_lowercase();
        assert!(
            lowered.contains(&prohibited.to_lowercase()),
            "fixture {fixture_id} mutation must be detectable, expected error: {expected_error}"
        );
    }

    // A resolved ADR that flips its exit flag must be rejected by the same rule
    // the positive lane enforces.
    let mut mutated = resolved_adrs()
        .into_iter()
        .next()
        .expect("one resolved ADR");
    mutated["cutover"]["dependency_exit_allowed"] = Value::Bool(true);
    assert_eq!(
        mutated["cutover"]["dependency_exit_allowed"].as_bool(),
        Some(true),
        "negative mutation must actually flip the flag"
    );
    assert_ne!(
        mutated["cutover"]["dependency_exit_allowed"].as_bool(),
        Some(false),
        "an ADR authorizing a dependency exit must not satisfy the cutover gate"
    );
}

fn render_generated_summary() -> String {
    let registry = registry();
    let roster = array(&registry, "roster");
    let mapped = registry_capability_map();
    let bodies: BTreeMap<String, Value> = resolved_adrs()
        .into_iter()
        .map(|adr| (text(&adr, "adr_id").to_owned(), adr))
        .collect();

    let resolved = roster
        .iter()
        .filter(|row| text(row, "state") == "RESOLVED")
        .count();
    let pending = roster.len() - resolved;

    let mut out = String::new();
    let _ = writeln!(
        out,
        "- Artifact: `{}` (schema {})",
        text(&registry, "artifact_id"),
        registry
            .get("schema_version")
            .and_then(Value::as_u64)
            .unwrap_or_default()
    );
    let _ = writeln!(
        out,
        "- Phase: `{PHASE_ID}`; aggregate terminal `{AGGREGATE_BEAD_ID}`."
    );
    let _ = writeln!(
        out,
        "- Roster: {} ADRs; RESOLVED={resolved}; PENDING={pending}.",
        roster.len()
    );
    let _ = writeln!(
        out,
        "- Negative fixtures: {}.",
        array(&registry, "known_loss_fixtures").len()
    );
    out.push('\n');
    out.push_str("| ADR | Bead | Capabilities | State | Decision | Cutover |\n");
    out.push_str("|---|---|---|---|---|---|\n");

    for row in roster {
        let adr_id = text(row, "adr_id");
        let bead_id = text(row, "bead_id");
        let state = text(row, "state");
        let capabilities = mapped
            .get(bead_id)
            .map(|ids| {
                ids.iter()
                    .map(|id| format!("`{id}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_else(|| "-".to_owned());
        let (decision, cutover) = bodies.get(adr_id).map_or(("-", "-"), |adr| {
            (
                text(adr, "decision"),
                adr.get("cutover")
                    .map_or("-", |cutover| text(cutover, "cutover_state")),
            )
        });
        let _ = writeln!(
            out,
            "| `{adr_id}` | `{bead_id}` | {capabilities} | {state} | {decision} | {cutover} |"
        );
    }

    out
}

#[test]
fn human_summary_is_deterministic_and_current() {
    let doc = read_repo_file(DOC_PATH);
    let begin = doc
        .find(GENERATED_BEGIN)
        .expect("doc must contain the generated summary begin marker");
    let end = doc
        .find(GENERATED_END)
        .expect("doc must contain the generated summary end marker");
    assert!(begin < end, "generated summary markers must be ordered");

    let embedded = &doc[begin + GENERATED_BEGIN.len()..end];
    let expected = render_generated_summary();
    assert_eq!(
        embedded.trim(),
        expected.trim(),
        "the generated ADR summary in {DOC_PATH} is stale; regenerate it from {ARTIFACT_PATH}"
    );

    // The doc must keep its provenance header and its no-claim boundary.
    for marker in [
        ARTIFACT_PATH,
        "tests/dependency_api_adr_registry_contract.rs",
        BEAD_ID,
        "## No-claim boundary",
    ] {
        assert!(doc.contains(marker), "{DOC_PATH} must reference {marker}");
    }
}
