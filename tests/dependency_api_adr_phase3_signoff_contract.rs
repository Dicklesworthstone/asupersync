//! Fail-closed terminal Phase-3 aggregate signoff for dependency sovereignty.
//!
//! Bead: asupersync-dep-p3-api-adrs-h3jspm.13
//! Scenario: api-adr-phase3-signoff
//! Fixture: artifacts/dependency_api_adr_phase3_signoff_v1.json
//!
//! The per-ADR lane (`dependency_api_adr_registry_contract`) proves each ADR
//! still describes the live crate. This lane proves the *set* is complete and
//! internally consistent: every capability is covered exactly once, every
//! capability has exactly one primary cutover authority, no row is UNKNOWN, no
//! ADR authorizes loss, every gap is owned by a live bead, and the negative
//! fixtures cover every ADR.
//!
//! Every row of the aggregate is re-derived from the live registries here, so a
//! stale row is a test failure rather than documentation drift.
//!
//! It proves nothing about runtime behavior, parity, or whether the planned
//! evidence has actually run.

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;

const BEAD_ID: &str = "asupersync-dep-p3-api-adrs-h3jspm.13";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const PHASE_ID: &str = "asupersync-dep-p3-api-adrs-h3jspm";
const ARTIFACT_PATH: &str = "artifacts/dependency_api_adr_phase3_signoff_v1.json";
const ADR_REGISTRY_PATH: &str = "artifacts/dependency_api_adr_registry_v1.json";
const CAPABILITY_REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const DOC_PATH: &str = "docs/dependency_api_adr_phase3_signoff.md";
const TRACKER_PATH: &str = ".beads/issues.jsonl";
const GENERATED_BEGIN: &str = "<!-- BEGIN GENERATED PHASE3 SIGNOFF SUMMARY -->";
const GENERATED_END: &str = "<!-- END GENERATED PHASE3 SIGNOFF SUMMARY -->";
const EXPECTED_ADR_COUNT: usize = 12;
const EXPECTED_CAPABILITY_COUNT: usize = 17;

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

fn signoff() -> Value {
    parse_repo_json(ARTIFACT_PATH)
}

fn adr_registry() -> Value {
    parse_repo_json(ADR_REGISTRY_PATH)
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

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_owned()
        })
        .collect()
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

/// Capability ids the capability registry maps to each ADR bead. The capability
/// registry is the authority; this aggregate restates nothing, so drift in
/// either direction fails closed.
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
        let Some(capability_ids) = rule.get("capability_ids").and_then(Value::as_array) else {
            continue;
        };
        mapped.insert(
            bead_id.to_owned(),
            capability_ids
                .iter()
                .filter_map(Value::as_str)
                .map(std::borrow::ToOwned::to_owned)
                .collect(),
        );
    }
    mapped
}

/// Capability rows keyed by id, for reconciling evidence owners and states.
fn capabilities_by_id() -> BTreeMap<String, Value> {
    let capability_registry = capability_registry();
    array(&capability_registry, "capabilities")
        .iter()
        .map(|row| (text(row, "capability_id").to_owned(), row.clone()))
        .collect()
}

fn resolved_adrs() -> BTreeMap<String, Value> {
    let registry = adr_registry();
    array(&registry, "adrs")
        .iter()
        .map(|row| (text(row, "adr_id").to_owned(), row.clone()))
        .collect()
}

#[test]
fn metadata_and_policy_are_fail_closed() {
    let artifact = signoff();
    assert_eq!(
        text(&artifact, "artifact_id"),
        "dependency-api-adr-phase3-signoff-v1"
    );
    assert_eq!(
        artifact.get("schema_version").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(text(&artifact, "program_id"), PROGRAM_ID);
    assert_eq!(text(&artifact, "phase_id"), PHASE_ID);
    assert_eq!(text(&artifact, "aggregate_bead_id"), BEAD_ID);
    assert_eq!(text(&artifact, "adr_registry_path"), ADR_REGISTRY_PATH);
    assert_eq!(
        text(&artifact, "capability_registry_path"),
        CAPABILITY_REGISTRY_PATH
    );
    assert_eq!(text(&artifact, "doc_path"), DOC_PATH);

    let policy = artifact
        .get("policy")
        .unwrap_or_else(|| panic!("policy must be present"));
    for key in [
        "purpose",
        "no_loss_rule",
        "authority_rule",
        "evidence_rule",
        "no_implementation_rule",
        "gap_rule",
        "truthful_baseline_rule",
        "aggregate_rule",
    ] {
        assert!(
            !text(policy, key).trim().is_empty(),
            "policy.{key} must be a non-empty statement"
        );
    }

    for key in [
        "allowed_terminal_decisions",
        "allowed_preserve_cutover_states",
        "allowed_surface_states",
        "allowed_platform_support",
    ] {
        assert!(
            !string_set(&artifact, key).is_empty(),
            "{key} must enumerate an allowed vocabulary"
        );
    }

    let validation = artifact
        .get("validation")
        .unwrap_or_else(|| panic!("validation must be present"));
    assert_eq!(
        text(validation, "contract_test"),
        "tests/dependency_api_adr_phase3_signoff_contract.rs"
    );
    assert_eq!(
        text(validation, "e2e_scenario_id"),
        "api-adr-phase3-signoff"
    );
    assert!(
        text(validation, "proof_command").contains("dependency_api_adr_phase3_signoff_contract"),
        "proof command must invoke this lane"
    );
    assert!(
        !array(validation, "checks").is_empty(),
        "validation.checks must be enumerated"
    );

    let boundary = text(validation, "no_claim_boundary");
    for phrase in [
        "does not prove",
        "authorizes no source change",
        "dependency cutover",
    ] {
        assert!(
            boundary.contains(phrase),
            "no_claim_boundary must contain {phrase:?}: {boundary}"
        );
    }
}

#[test]
fn all_twelve_adrs_are_owner_resolved() {
    let artifact = signoff();
    let registry = adr_registry();

    assert_eq!(
        artifact.get("expected_adr_count").and_then(Value::as_u64),
        Some(EXPECTED_ADR_COUNT as u64)
    );

    let roster = array(&registry, "roster");
    assert_eq!(
        roster.len(),
        EXPECTED_ADR_COUNT,
        "the phase roster must carry exactly {EXPECTED_ADR_COUNT} ADRs"
    );

    let pending: Vec<&str> = roster
        .iter()
        .filter(|row| text(row, "state") != "RESOLVED")
        .map(|row| text(row, "adr_id"))
        .collect();
    assert!(
        pending.is_empty(),
        "the terminal gate may not close while any ADR is unresolved: {pending:?}"
    );

    assert_eq!(
        resolved_adrs().len(),
        EXPECTED_ADR_COUNT,
        "every roster row must have a resolved body"
    );
}

#[test]
fn the_decision_matrix_rederives_from_the_live_adr_registry() {
    let artifact = signoff();
    let adrs = resolved_adrs();
    let mapped = registry_capability_map();
    let allowed_decisions = string_set(&artifact, "allowed_terminal_decisions");
    let allowed_cutover = string_set(&artifact, "allowed_preserve_cutover_states");

    let matrix = array(&artifact, "decision_matrix");
    assert_eq!(
        matrix.len(),
        EXPECTED_ADR_COUNT,
        "the decision matrix must have one row per ADR"
    );

    for row in matrix {
        let adr_id = text(row, "adr_id");
        let adr = adrs
            .get(adr_id)
            .unwrap_or_else(|| panic!("{adr_id} is in the matrix but not in the ADR registry"));

        assert_eq!(
            text(row, "bead_id"),
            text(adr, "bead_id"),
            "{adr_id} bead id drifted"
        );
        assert_eq!(
            text(row, "decision"),
            text(adr, "decision"),
            "{adr_id} decision drifted"
        );
        assert!(
            allowed_decisions.contains(text(row, "decision")),
            "{adr_id} decision {:?} is not an allowed terminal decision",
            text(row, "decision")
        );
        assert_eq!(
            text(row, "doc_path"),
            text(adr, "doc_path"),
            "{adr_id} doc path drifted"
        );
        assert_eq!(
            text(row, "evidence_state"),
            text(
                adr.get("evidence")
                    .unwrap_or_else(|| panic!("{adr_id} evidence must be present")),
                "state"
            ),
            "{adr_id} evidence state drifted"
        );

        let declared_capabilities = string_set(row, "capability_ids");
        let live_capabilities: BTreeSet<String> = mapped
            .get(text(adr, "bead_id"))
            .unwrap_or_else(|| panic!("{adr_id} bead has no capability mapping"))
            .iter()
            .cloned()
            .collect();
        assert_eq!(
            declared_capabilities, live_capabilities,
            "{adr_id} capability ids drifted from the live bead mapping rules"
        );

        let cutover = adr
            .get("cutover")
            .unwrap_or_else(|| panic!("{adr_id} cutover must be present"));
        let live_states: BTreeSet<String> = array(cutover, "per_capability")
            .iter()
            .map(|entry| text(entry, "cutover_state").to_owned())
            .collect();
        assert_eq!(
            string_set(row, "cutover_states"),
            live_states,
            "{adr_id} cutover states drifted"
        );
        for state in &live_states {
            assert!(
                allowed_cutover.contains(state),
                "{adr_id} cutover state {state:?} is not a preserving state"
            );
        }

        assert_eq!(
            row.get("dependency_exit_allowed").and_then(Value::as_bool),
            cutover
                .get("dependency_exit_allowed")
                .and_then(Value::as_bool),
            "{adr_id} dependency-exit flag drifted"
        );

        for (key, field) in [
            ("known_gap_count", "known_gaps"),
            ("user_journey_count", "user_journeys"),
            ("platform_cell_count", "platform_cells"),
            ("supersedes_count", "supersedes"),
        ] {
            assert_eq!(
                row.get(key).and_then(Value::as_u64),
                Some(array(adr, field).len() as u64),
                "{adr_id} {key} drifted from the live {field} list"
            );
        }

        let mut live_surface_states: BTreeMap<String, u64> = BTreeMap::new();
        for surface in array(adr, "preserved_surfaces") {
            *live_surface_states
                .entry(text(surface, "state").to_owned())
                .or_default() += 1;
        }
        let declared = row
            .get("surface_states")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{adr_id} surface_states must be an object"));
        assert_eq!(
            declared.len(),
            live_surface_states.len(),
            "{adr_id} surface-state histogram drifted"
        );
        for (state, count) in &live_surface_states {
            assert_eq!(
                declared.get(state).and_then(Value::as_u64),
                Some(*count),
                "{adr_id} surface-state count for {state} drifted"
            );
        }
    }
}

#[test]
fn capability_coverage_is_exact_and_each_capability_is_claimed_once() {
    let artifact = signoff();
    let mapped = registry_capability_map();
    let adrs = resolved_adrs();

    let coverage = array(&artifact, "capability_coverage");
    assert_eq!(
        artifact
            .get("expected_capability_count")
            .and_then(Value::as_u64),
        Some(EXPECTED_CAPABILITY_COUNT as u64)
    );
    assert_eq!(
        coverage.len(),
        EXPECTED_CAPABILITY_COUNT,
        "capability coverage must have one row per covered capability"
    );

    // Every capability the live mapping assigns to a Phase-3 ADR bead must
    // appear exactly once. Claiming one twice would mean two primary
    // authorities for the same capability.
    let mut live: BTreeMap<String, String> = BTreeMap::new();
    for adr in adrs.values() {
        let adr_id = text(adr, "adr_id").to_owned();
        for capability_id in mapped
            .get(text(adr, "bead_id"))
            .unwrap_or_else(|| panic!("{adr_id} bead has no capability mapping"))
        {
            let previous = live.insert(capability_id.clone(), adr_id.clone());
            assert!(
                previous.is_none(),
                "{capability_id} is claimed by both {} and {adr_id}",
                previous.unwrap_or_default()
            );
        }
    }

    let declared: BTreeMap<String, String> = coverage
        .iter()
        .map(|row| {
            (
                text(row, "capability_id").to_owned(),
                text(row, "adr_id").to_owned(),
            )
        })
        .collect();
    assert_eq!(
        declared.len(),
        coverage.len(),
        "capability coverage contains a duplicate capability id"
    );
    assert_eq!(
        declared, live,
        "capability coverage drifted from the live bead mapping rules"
    );

    // The per-capability disposition and cutover state must match the ADR body.
    for row in coverage {
        let capability_id = text(row, "capability_id");
        let adr = adrs
            .get(text(row, "adr_id"))
            .unwrap_or_else(|| panic!("{capability_id} names an unknown ADR"));
        let entry = array(
            adr.get("cutover")
                .unwrap_or_else(|| panic!("cutover must be present")),
            "per_capability",
        )
        .iter()
        .find(|entry| text(entry, "capability_id") == capability_id)
        .unwrap_or_else(|| panic!("{capability_id} has no per-capability cutover row"));
        assert_eq!(
            text(row, "disposition"),
            text(entry, "disposition"),
            "{capability_id} disposition drifted"
        );
        assert_eq!(
            text(row, "cutover_state"),
            text(entry, "cutover_state"),
            "{capability_id} cutover state drifted"
        );
    }
}

#[test]
fn no_adr_row_is_unknown() {
    let artifact = signoff();
    let adrs = resolved_adrs();
    let mapped = registry_capability_map();
    let allowed_surface_states = string_set(&artifact, "allowed_surface_states");
    let allowed_platform_support = string_set(&artifact, "allowed_platform_support");

    for (adr_id, adr) in &adrs {
        assert!(
            !mapped
                .get(text(adr, "bead_id"))
                .map(Vec::is_empty)
                .unwrap_or(true),
            "{adr_id} has no capability row"
        );

        for field in [
            "preserved_public_symbols",
            "preserved_feature_flags",
            "preserved_surfaces",
            "preserved_config_semantics",
            "platform_cells",
            "user_journeys",
            "downstream_consumers",
            "security_invariants",
            "cancellation_invariants",
        ] {
            assert!(
                !array(adr, field).is_empty(),
                "{adr_id} has an empty {field} row"
            );
        }

        for surface in array(adr, "preserved_surfaces") {
            let state = text(surface, "state");
            assert!(
                allowed_surface_states.contains(state),
                "{adr_id} surface {:?} has unknown state {state:?}",
                text(surface, "surface")
            );
            // A not-shipped surface must not claim entry points; anything else
            // must say where it lives.
            if state == "NOT_SHIPPED" {
                assert!(
                    array(surface, "public_entry_points").is_empty(),
                    "{adr_id} surface {:?} is NOT_SHIPPED but declares entry points",
                    text(surface, "surface")
                );
            } else {
                assert!(
                    !text(surface, "implementation").trim().is_empty(),
                    "{adr_id} surface {:?} is shipped but names no implementation",
                    text(surface, "surface")
                );
            }
        }

        for cell in array(adr, "platform_cells") {
            let support = text(cell, "support");
            assert!(
                allowed_platform_support.contains(support),
                "{adr_id} platform cell {:?} has unknown support {support:?}",
                text(cell, "target_family")
            );
        }

        let ecosystem = adr
            .get("external_ecosystem_integration")
            .unwrap_or_else(|| panic!("{adr_id} must declare ecosystem integration"));
        assert!(
            !text(ecosystem, "removal_precondition").trim().is_empty(),
            "{adr_id} must state a removal precondition"
        );
        assert_eq!(
            ecosystem.get("must_remain").and_then(Value::as_bool),
            Some(true),
            "{adr_id} ecosystem integration must be marked must_remain"
        );

        for journey in array(adr, "user_journeys") {
            assert!(
                !text(journey, "id").trim().is_empty()
                    && !text(journey, "description").trim().is_empty(),
                "{adr_id} has an unnamed user journey"
            );
        }

        assert!(
            !text(adr, "no_claim_boundary").trim().is_empty(),
            "{adr_id} must state a no-claim boundary"
        );
    }
}

#[test]
fn every_capability_has_exactly_one_primary_authority() {
    let artifact = signoff();
    let adrs = resolved_adrs();

    let mut claimed: BTreeMap<String, String> = BTreeMap::new();
    for row in array(&artifact, "capability_coverage") {
        let capability_id = text(row, "capability_id");
        let primaries = string_set(row, "primary_authorities");
        assert!(
            !primaries.is_empty(),
            "{capability_id} declares no primary cutover authority"
        );

        let secondaries = string_set(row, "secondary_compatibility_consumers");
        let overlap: Vec<&String> = primaries.intersection(&secondaries).collect();
        assert!(
            overlap.is_empty(),
            "{capability_id} lists {overlap:?} as both primary authority and secondary consumer"
        );

        // The authority set must match the owning ADR body exactly.
        let adr = adrs
            .get(text(row, "adr_id"))
            .unwrap_or_else(|| panic!("{capability_id} names an unknown ADR"));
        let cutover = adr
            .get("cutover")
            .unwrap_or_else(|| panic!("cutover must be present"));
        assert_eq!(
            primaries,
            string_set(cutover, "primary_authorities"),
            "{capability_id} primary authority drifted from its ADR"
        );

        for primary in &primaries {
            if let Some(previous) = claimed.insert(primary.clone(), capability_id.to_owned()) {
                // Two capabilities may legitimately share a campaign root only
                // when the same ADR owns both; a cross-ADR collision is a
                // genuine ambiguity about who decides.
                let previous_adr = array(&artifact, "capability_coverage")
                    .iter()
                    .find(|other| text(other, "capability_id") == previous)
                    .map(|other| text(other, "adr_id").to_owned())
                    .unwrap_or_default();
                assert_eq!(
                    previous_adr,
                    text(row, "adr_id"),
                    "{primary} is primary authority for {previous} and {capability_id} \
                     across different ADRs"
                );
            }
        }
    }
}

#[test]
fn every_adr_declares_evidence_that_reconciles_with_the_capability_registry() {
    let adrs = resolved_adrs();
    let mapped = registry_capability_map();
    let capabilities = capabilities_by_id();

    for (adr_id, adr) in &adrs {
        let evidence = adr
            .get("evidence")
            .unwrap_or_else(|| panic!("{adr_id} must declare evidence"));
        for key in ["state", "baseline_owner", "unit_test_owner", "e2e_owner"] {
            assert!(
                !text(evidence, key).trim().is_empty(),
                "{adr_id} evidence.{key} must be populated"
            );
        }
        assert!(
            !array(evidence, "required_evidence_classes").is_empty(),
            "{adr_id} must enumerate required evidence classes"
        );
        assert!(
            !text(evidence, "note").trim().is_empty(),
            "{adr_id} evidence must carry an honesty note"
        );

        let capability_ids = mapped
            .get(text(adr, "bead_id"))
            .unwrap_or_else(|| panic!("{adr_id} bead has no capability mapping"));

        // Scenario ids are the union across the ADR's capabilities: an ADR may
        // not invent a scenario, nor drop one its capabilities declare.
        let mut expected_scenarios = BTreeSet::new();
        let mut baseline_owners = BTreeSet::new();
        let mut unit_owners = BTreeSet::new();
        let mut e2e_owners = BTreeSet::new();
        let mut evidence_states = BTreeSet::new();
        for capability_id in capability_ids {
            let capability = capabilities
                .get(capability_id)
                .unwrap_or_else(|| panic!("{capability_id} is not in the capability registry"));
            expected_scenarios.extend(string_set(capability, "scenario_ids"));
            baseline_owners.insert(
                text(
                    capability
                        .get("baseline")
                        .unwrap_or_else(|| panic!("{capability_id} baseline must be present")),
                    "owner_bead",
                )
                .to_owned(),
            );
            unit_owners.insert(text(capability, "unit_test_owner").to_owned());
            e2e_owners.insert(text(capability, "e2e_owner").to_owned());
            evidence_states.insert(text(capability, "evidence_state").to_owned());
        }

        assert_eq!(
            string_set(evidence, "scenario_ids"),
            expected_scenarios,
            "{adr_id} scenario ids drifted from its capabilities"
        );
        assert_eq!(
            evidence_states,
            BTreeSet::from([text(evidence, "state").to_owned()]),
            "{adr_id} evidence state disagrees with its capabilities"
        );

        // A multi-capability ADR names one representative owner per class; a
        // single-capability ADR must match exactly. Membership covers both.
        for (key, pool) in [
            ("baseline_owner", &baseline_owners),
            ("unit_test_owner", &unit_owners),
            ("e2e_owner", &e2e_owners),
        ] {
            assert!(
                pool.contains(text(evidence, key)),
                "{adr_id} evidence.{key} {:?} is not an owner of any of its capabilities {pool:?}",
                text(evidence, key)
            );
        }
    }
}

#[test]
fn every_adr_forbids_shims_and_carries_a_complete_rollback_policy() {
    let adrs = resolved_adrs();

    for (adr_id, adr) in &adrs {
        let migration = adr
            .get("migration_policy")
            .unwrap_or_else(|| panic!("{adr_id} must declare a migration policy"));
        assert_eq!(
            text(migration, "compatibility_shims"),
            "forbidden",
            "{adr_id} must forbid compatibility shims"
        );
        for key in ["additive_only", "sequencing", "docs_obligation"] {
            assert!(
                !text(migration, key).trim().is_empty(),
                "{adr_id} migration_policy.{key} must be populated"
            );
        }

        let rollback = adr
            .get("rollback_policy")
            .unwrap_or_else(|| panic!("{adr_id} must declare a rollback policy"));
        for key in ["trigger", "action", "verification"] {
            assert!(
                !text(rollback, key).trim().is_empty(),
                "{adr_id} rollback_policy.{key} must be populated"
            );
        }

        assert!(
            !array(adr, "alternatives_considered").is_empty(),
            "{adr_id} must record the alternatives it rejected"
        );
        for alternative in array(adr, "alternatives_considered") {
            assert!(
                !text(alternative, "rejected_because").trim().is_empty(),
                "{adr_id} rejected an alternative without saying why"
            );
        }
    }
}

#[test]
fn no_resolved_adr_authorizes_loss_and_no_gap_may_widen() {
    let artifact = signoff();
    let adrs = resolved_adrs();
    let allowed_cutover = string_set(&artifact, "allowed_preserve_cutover_states");

    for (adr_id, adr) in &adrs {
        let cutover = adr
            .get("cutover")
            .unwrap_or_else(|| panic!("{adr_id} cutover must be present"));
        assert_eq!(
            cutover
                .get("dependency_exit_allowed")
                .and_then(Value::as_bool),
            Some(false),
            "{adr_id} authorizes a dependency exit; the terminal gate forbids it"
        );

        for entry in array(cutover, "per_capability") {
            let state = text(entry, "cutover_state");
            assert!(
                allowed_cutover.contains(state),
                "{adr_id} capability {:?} has non-preserving cutover state {state:?}",
                text(entry, "capability_id")
            );
        }

        for gap in array(adr, "known_gaps") {
            assert_eq!(
                gap.get("may_widen").and_then(Value::as_bool),
                Some(false),
                "{adr_id} gap {:?} is marked wideable",
                text(gap, "gap_id")
            );
        }

        let delta = adr
            .get("api_surface_delta")
            .unwrap_or_else(|| panic!("{adr_id} must declare an api surface delta"));
        assert!(
            array(delta, "root_exports_removed").is_empty(),
            "{adr_id} removes a root export"
        );
    }

    let ledger = artifact
        .get("gap_ledger")
        .unwrap_or_else(|| panic!("gap_ledger must be present"));
    let live_gaps: usize = adrs
        .values()
        .map(|adr| array(adr, "known_gaps").len())
        .sum();
    assert_eq!(
        ledger.get("total_known_gaps").and_then(Value::as_u64),
        Some(live_gaps as u64),
        "gap ledger total drifted from the live ADRs"
    );
    assert_eq!(
        ledger
            .get("all_marked_non_wideable")
            .and_then(Value::as_bool),
        Some(true)
    );
}

#[test]
fn the_negative_fixture_review_covers_every_adr() {
    let artifact = signoff();
    let registry = adr_registry();
    let adrs = resolved_adrs();

    let review = artifact
        .get("negative_fixture_review")
        .unwrap_or_else(|| panic!("negative_fixture_review must be present"));
    assert_eq!(text(review, "verdict"), "COMPLETE");
    assert!(!text(review, "method").trim().is_empty());

    let live_fixtures = array(&registry, "known_loss_fixtures");
    let declared = array(review, "fixtures");
    assert_eq!(
        declared.len(),
        live_fixtures.len(),
        "the fixture review drifted from the ADR registry"
    );
    assert_eq!(
        artifact
            .get("expected_fixture_count")
            .and_then(Value::as_u64),
        Some(live_fixtures.len() as u64)
    );

    let mut fixture_ids = BTreeSet::new();
    let mut prohibited = BTreeSet::new();
    let mut covered = BTreeSet::new();
    for fixture in live_fixtures {
        let fixture_id = text(fixture, "fixture_id");
        assert!(
            fixture_ids.insert(fixture_id.to_owned()),
            "duplicate fixture id {fixture_id}"
        );
        assert!(
            prohibited.insert(text(fixture, "prohibited_text").to_lowercase()),
            "duplicate prohibited text in {fixture_id}"
        );
        let adr_id = text(fixture, "adr_id");
        assert!(
            adrs.contains_key(adr_id),
            "fixture {fixture_id} names unknown ADR {adr_id}"
        );
        assert!(
            !text(fixture, "expected_error").trim().is_empty(),
            "fixture {fixture_id} names no expected error"
        );
        covered.insert(adr_id.to_owned());
    }

    let uncovered: Vec<&String> = adrs.keys().filter(|id| !covered.contains(*id)).collect();
    assert!(
        uncovered.is_empty(),
        "these ADRs have no negative fixture: {uncovered:?}"
    );

    // The declared review rows must match the live fixtures exactly.
    let live_pairs: BTreeSet<(String, String)> = live_fixtures
        .iter()
        .map(|fixture| {
            (
                text(fixture, "fixture_id").to_owned(),
                text(fixture, "adr_id").to_owned(),
            )
        })
        .collect();
    let declared_pairs: BTreeSet<(String, String)> = declared
        .iter()
        .map(|fixture| {
            (
                text(fixture, "fixture_id").to_owned(),
                text(fixture, "adr_id").to_owned(),
            )
        })
        .collect();
    assert_eq!(
        declared_pairs, live_pairs,
        "the fixture review does not match the live fixtures"
    );
}

#[test]
fn every_referenced_bead_is_live_in_the_tracker() {
    let artifact = signoff();
    let adrs = resolved_adrs();
    let live = live_bead_ids();

    let mut referenced: BTreeSet<String> = BTreeSet::new();
    referenced.insert(BEAD_ID.to_owned());
    for adr in adrs.values() {
        referenced.insert(text(adr, "bead_id").to_owned());
        for gap in array(adr, "known_gaps") {
            referenced.insert(text(gap, "owner_bead").to_owned());
        }
        let cutover = adr
            .get("cutover")
            .unwrap_or_else(|| panic!("cutover must be present"));
        referenced.extend(string_set(cutover, "primary_authorities"));
        referenced.extend(string_set(cutover, "secondary_compatibility_consumers"));
    }
    for dependent in array(&artifact, "downstream_dependents") {
        referenced.insert(text(dependent, "bead_id").to_owned());
    }
    referenced.insert(
        text(
            artifact
                .get("registry_defect_ledger")
                .unwrap_or_else(|| panic!("registry_defect_ledger must be present")),
            "owner_bead",
        )
        .to_owned(),
    );

    let missing: Vec<&String> = referenced.iter().filter(|id| !live.contains(*id)).collect();
    assert!(
        missing.is_empty(),
        "these referenced beads are absent from the tracker: {missing:?}"
    );

    let ledger = artifact
        .get("gap_ledger")
        .unwrap_or_else(|| panic!("gap_ledger must be present"));
    let distinct_owners: BTreeSet<String> = adrs
        .values()
        .flat_map(|adr| array(adr, "known_gaps"))
        .map(|gap| text(gap, "owner_bead").to_owned())
        .collect();
    assert_eq!(
        ledger.get("distinct_owner_beads").and_then(Value::as_u64),
        Some(distinct_owners.len() as u64),
        "gap ledger owner count drifted"
    );
}

#[test]
fn declared_downstream_dependents_actually_depend_on_this_gate() {
    let artifact = signoff();
    let tracker = read_repo_file(TRACKER_PATH);

    let declared = array(&artifact, "downstream_dependents");
    assert!(
        !declared.is_empty(),
        "the terminal gate must name what it unblocks"
    );

    for dependent in declared {
        let bead_id = text(dependent, "bead_id");
        assert_eq!(text(dependent, "relation"), "blocks");
        assert!(
            !text(dependent, "title").trim().is_empty(),
            "{bead_id} must carry a title"
        );

        // Find the dependent's tracker row and confirm it really lists this
        // aggregate as a dependency, rather than the artifact asserting it.
        let row = tracker
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .find(|value| value.get("id").and_then(Value::as_str) == Some(bead_id))
            .unwrap_or_else(|| panic!("{bead_id} is not in the tracker"));
        let serialized = row.to_string();
        assert!(
            serialized.contains(BEAD_ID),
            "{bead_id} does not reference {BEAD_ID} as a dependency"
        );
    }
}

#[test]
fn declared_paths_exist() {
    let artifact = signoff();
    let adrs = resolved_adrs();

    for path in [
        text(&artifact, "adr_registry_path"),
        text(&artifact, "capability_registry_path"),
        text(&artifact, "doc_path"),
    ] {
        assert!(
            repo_root().join(path).exists(),
            "declared path {path} does not exist"
        );
    }

    let adr_doc_dir = text(&artifact, "adr_doc_dir");
    assert!(
        repo_root().join(adr_doc_dir).is_dir(),
        "{adr_doc_dir} must be a directory"
    );

    for (adr_id, adr) in &adrs {
        let doc_path = text(adr, "doc_path");
        assert!(
            repo_root().join(doc_path).exists(),
            "{adr_id} narrative {doc_path} does not exist"
        );
        assert!(
            doc_path.starts_with(adr_doc_dir),
            "{adr_id} narrative must live under {adr_doc_dir}"
        );
    }
}

#[test]
fn human_summary_is_deterministic_and_current() {
    let artifact = signoff();
    let doc = read_repo_file(DOC_PATH);

    let begin = doc
        .find(GENERATED_BEGIN)
        .unwrap_or_else(|| panic!("{DOC_PATH} must contain {GENERATED_BEGIN}"));
    let end = doc
        .find(GENERATED_END)
        .unwrap_or_else(|| panic!("{DOC_PATH} must contain {GENERATED_END}"));
    assert!(begin < end, "generated markers are out of order");
    let block = doc[begin + GENERATED_BEGIN.len()..end].trim();

    let mut expected = String::new();
    let matrix = array(&artifact, "decision_matrix");
    let coverage = array(&artifact, "capability_coverage");
    let gap_ledger = artifact
        .get("gap_ledger")
        .unwrap_or_else(|| panic!("gap_ledger must be present"));

    writeln!(
        expected,
        "- Artifact: `{}` (schema {})",
        text(&artifact, "artifact_id"),
        artifact
            .get("schema_version")
            .and_then(Value::as_u64)
            .unwrap_or_default()
    )
    .expect("write");
    writeln!(
        expected,
        "- Aggregate bead: `{}`; phase `{}`.",
        text(&artifact, "aggregate_bead_id"),
        text(&artifact, "phase_id")
    )
    .expect("write");
    writeln!(
        expected,
        "- ADRs: {} resolved, 0 pending. Capabilities covered: {}.",
        matrix.len(),
        coverage.len()
    )
    .expect("write");
    writeln!(
        expected,
        "- Known gaps: {} across {} owner beads. Negative fixtures: {}.",
        gap_ledger
            .get("total_known_gaps")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        gap_ledger
            .get("distinct_owner_beads")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        array(
            artifact
                .get("negative_fixture_review")
                .unwrap_or_else(|| panic!("review must be present")),
            "fixtures"
        )
        .len()
    )
    .expect("write");
    expected.push('\n');
    writeln!(
        expected,
        "| ADR | Capabilities | Decision | Cutover | Gaps |"
    )
    .expect("write");
    writeln!(expected, "|---|---|---|---|---|").expect("write");
    for row in matrix {
        let capabilities = string_set(row, "capability_ids")
            .into_iter()
            .map(|id| format!("`{id}`"))
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(
            expected,
            "| `{}` | {} | {} | {} | {} |",
            text(row, "adr_id"),
            capabilities,
            text(row, "decision"),
            string_set(row, "cutover_states")
                .into_iter()
                .collect::<Vec<_>>()
                .join(" / "),
            row.get("known_gap_count")
                .and_then(Value::as_u64)
                .unwrap_or_default()
        )
        .expect("write");
    }

    assert_eq!(
        block,
        expected.trim(),
        "{DOC_PATH} generated summary is stale; regenerate it"
    );
}
