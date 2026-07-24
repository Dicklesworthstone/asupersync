//! Fail-closed TOML/config capability inventory contract.
//!
//! Bead: asupersync-5z2scg.4.1
//! Scenario: config-toml-capability-inventory-contract
//! Fixture: artifacts/config_toml_capability_inventory_v1.json
//!
//! This proves source-pinned surface, field, grammar, precedence, I/O, error,
//! corpus, downstream, child-owner, and gap inventories. It does not prove
//! arbitrary TOML, real binary journeys, JSON parity, or permission to remove
//! the incumbent `toml` dependency.

#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::PathBuf;

const ARTIFACT_PATH: &str = "artifacts/config_toml_capability_inventory_v1.json";
const DOC_PATH: &str = "docs/config_toml_capability_inventory.md";
const ADR_PATH: &str = "docs/adr/dep_plan_adr_004_config_scenario_formats.md";
const CAPABILITY_REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const API_SURFACE_MAP_PATH: &str = "artifacts/api_surface_map_v1.json";
const BEAD_ID: &str = "asupersync-5z2scg.4.1";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const CAPABILITY_ID: &str = "CAP-CONFIG-TOML-JSON";
const ADR_ID: &str = "DEP-ADR-004";
const BASELINE_REVISION: &str = "3468d4474e981fd2b19a8020175e6bb8bd4a5dc3";
const AUTHORITY_REVISION: &str = "673a905631c5580cdc8037315569b72bd636ecca";
const DOC_BEGIN: &str = "<!-- BEGIN CONFIG TOML CAPABILITY INVENTORY -->";
const DOC_END: &str = "<!-- END CONFIG TOML CAPABILITY INVENTORY -->";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn read_repo_bytes(path: &str) -> Vec<u8> {
    std::fs::read(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn parse_repo_json(path: &str) -> Value {
    serde_json::from_str(&read_repo_file(path))
        .unwrap_or_else(|error| panic!("{path} must be valid JSON: {error}"))
}

fn artifact() -> Value {
    parse_repo_json(ARTIFACT_PATH)
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

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn row_ids(rows: &[Value], key: &str) -> BTreeSet<String> {
    rows.iter().map(|row| text(row, key).to_owned()).collect()
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

fn find_row<'a>(rows: &'a [Value], key: &str, expected: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing {key}={expected}"))
}

fn validate_state_fields(value: &Value, path: &str) -> Result<(), String> {
    match value {
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_state_fields(child, &format!("{path}[{index}]"))?;
            }
        }
        Value::Object(values) => {
            for (key, child) in values {
                let child_path = format!("{path}.{key}");
                if matches!(key.as_str(), "inventory_state" | "evidence_state")
                    && child.as_str() == Some("UNKNOWN")
                {
                    return Err(format!("{child_path} must not be UNKNOWN"));
                }
                validate_state_fields(child, &child_path)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_inventory(inventory: &Value) -> Result<(), String> {
    if inventory.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("schema_version must be 1".to_owned());
    }
    for (key, expected) in [
        ("artifact_id", "config-toml-capability-inventory-v1"),
        ("program_id", PROGRAM_ID),
        ("bead_id", BEAD_ID),
        ("capability_id", CAPABILITY_ID),
        ("baseline_revision", BASELINE_REVISION),
        ("authority_revision", AUTHORITY_REVISION),
    ] {
        if inventory.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("{key} must be {expected}"));
        }
    }

    let authority = object(inventory, "authority");
    for (key, expected) in [
        ("adr_id", ADR_ID),
        ("decision", "ADDITIVE_COEXISTENCE"),
        ("disposition", "KEEP_UNTIL_PARITY"),
        ("cutover_state", "KEEP_INCUMBENT"),
    ] {
        if authority.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("authority.{key} must be {expected}"));
        }
    }
    if authority
        .get("dependency_exit_allowed")
        .and_then(Value::as_bool)
        != Some(false)
    {
        return Err("authority must forbid dependency exit".to_owned());
    }

    let policy = object(inventory, "policy");
    if policy.get("zero_unknown_required").and_then(Value::as_bool) != Some(true)
        || policy.get("unknown_rows").and_then(Value::as_u64) != Some(0)
    {
        return Err("policy must require and report zero unknown rows".to_owned());
    }
    for key in ["allowed_inventory_states", "allowed_evidence_states"] {
        if string_set(inventory.get("policy").expect("policy"), key).contains("UNKNOWN") {
            return Err(format!("{key} must not permit UNKNOWN"));
        }
    }
    validate_state_fields(inventory, "$")?;

    let expected_profiles: BTreeSet<String> = [
        "CFG-PROFILE-DEFAULT",
        "CFG-PROFILE-CONFIG-FILE",
        "CFG-PROFILE-CLI",
        "CFG-PROFILE-ATPD",
        "CFG-PROFILE-DEPENDENCY-LEDGER",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if row_ids(array(inventory, "feature_profiles"), "profile_id") != expected_profiles {
        return Err("feature profiles must cover the exact five live build profiles".to_owned());
    }

    let expected_surfaces: BTreeSet<String> = [
        "CFG-TOML-RUNTIME",
        "CFG-TOML-ATP-COMMAND",
        "CFG-TOML-ATP-INSTALL",
        "CFG-TOML-ATPD",
        "CFG-TOML-DEPENDENCY-LEDGER",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let surfaces = array(inventory, "toml_surfaces");
    if row_ids(surfaces, "surface_id") != expected_surfaces {
        return Err("production/internal TOML surface inventory drifted".to_owned());
    }
    for (surface_id, field_count) in [
        ("CFG-TOML-RUNTIME", 14),
        ("CFG-TOML-ATP-COMMAND", 11),
        ("CFG-TOML-ATP-INSTALL", 14),
        ("CFG-TOML-ATPD", 45),
        ("CFG-TOML-DEPENDENCY-LEDGER", 0),
    ] {
        let row = find_row(surfaces, "surface_id", surface_id);
        if row.get("field_count").and_then(Value::as_u64) != Some(field_count) {
            return Err(format!(
                "{surface_id} field count must remain {field_count}"
            ));
        }
        let enumerated = array(row, "field_groups")
            .iter()
            .map(|group| array(group, "fields").len())
            .sum::<usize>();
        if enumerated != field_count as usize {
            return Err(format!(
                "{surface_id} enumerates {enumerated} fields, expected {field_count}"
            ));
        }
    }

    let expected_adjacent: BTreeSet<String> = [
        "CFG-TOML-FRANKEN-DECISION-TEST",
        "CFG-TOML-MOCK-METAMORPHIC",
        "CFG-NON-TOML-RAPTORQ",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if row_ids(array(inventory, "adjacent_surfaces"), "surface_id") != expected_adjacent {
        return Err("adjacent test-only and non-TOML surface inventory drifted".to_owned());
    }

    let grammar = array(inventory, "grammar_constructs");
    if grammar.len() != 16 || row_ids(grammar, "construct_id").len() != 16 {
        return Err("grammar inventory must contain sixteen unique constructs".to_owned());
    }
    let precedence = array(inventory, "precedence_contracts");
    if row_ids(precedence, "precedence_id")
        != surfaces
            .iter()
            .map(|row| text(row, "precedence_id").to_owned())
            .collect()
    {
        return Err("every TOML surface must route to one precedence contract".to_owned());
    }

    let errors = array(inventory, "error_contracts");
    if errors.len() != 12 || row_ids(errors, "error_id").len() != 12 {
        return Err("error inventory must contain twelve unique distinctions".to_owned());
    }
    for row in surfaces {
        for error_id in array(row, "error_contract_ids") {
            let error_id = error_id
                .as_str()
                .ok_or_else(|| "surface error ids must be strings".to_owned())?;
            if !errors.iter().any(|candidate| {
                candidate.get("error_id").and_then(Value::as_str) == Some(error_id)
            }) {
                return Err(format!(
                    "{} references missing {error_id}",
                    text(row, "surface_id")
                ));
            }
        }
    }

    let corpus = array(inventory, "corpus_cases");
    if corpus.len() != 27 || row_ids(corpus, "case_id").len() != 27 {
        return Err("corpus must contain twenty-seven unique cases".to_owned());
    }
    let required_classes: BTreeSet<String> = [
        "empty",
        "valid-scalars",
        "valid-collections",
        "valid-comments-formatting",
        "malformed-duplicate",
        "malformed-conflict",
        "malformed-syntax",
        "generic-value-boundary",
        "valid-all-fields",
        "unknown-security-adjacent",
        "malformed-type",
        "semantic-error",
        "valid-boundary",
        "unknown-field",
        "malformed-enum",
        "programmatic-precedence-boundary",
        "valid-write-read",
        "path-security-error",
        "missing-file",
        "unknown-security-field",
        "valid-cargo-manifest-shapes",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let actual_classes: BTreeSet<String> = corpus
        .iter()
        .map(|row| text(row, "class").to_owned())
        .collect();
    if !required_classes.is_subset(&actual_classes) {
        return Err("corpus is missing a required happy, boundary, or error class".to_owned());
    }

    let expected_children: BTreeSet<String> = (1..=5)
        .map(|suffix| format!("asupersync-5z2scg.4.{suffix}"))
        .collect();
    let children = array(inventory, "child_capability_rows");
    if row_ids(children, "owner_bead") != expected_children {
        return Err("every CFG A1-A5 child must own exactly one row".to_owned());
    }
    for row in children {
        if array(row, "required_evidence").is_empty() || text(row, "no_claim").trim().is_empty() {
            return Err(format!(
                "{} must name evidence and a no-claim boundary",
                text(row, "owner_bead")
            ));
        }
    }

    let expected_gaps: BTreeSet<String> = [1_u8, 2, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]
        .into_iter()
        .map(|suffix| format!("CFG-GAP-{suffix:02}"))
        .collect();
    let gaps = array(inventory, "known_gaps");
    if row_ids(gaps, "gap_id") != expected_gaps {
        return Err("known config gaps must retain the exact routed set".to_owned());
    }
    for row in gaps {
        if text(row, "owner_bead").is_empty() || text(row, "evidence_state") != "BLOCKED_GAP" {
            return Err(format!(
                "{} must be routed and fail closed",
                text(row, "gap_id")
            ));
        }
    }

    let consumers = array(inventory, "downstream_files_and_consumers");
    if consumers.len() != 7 || row_ids(consumers, "consumer_id").len() != 7 {
        return Err("downstream inventory must contain seven unique consumers".to_owned());
    }
    if text(inventory, "no_claim_boundary").trim().is_empty() {
        return Err("top-level no-claim boundary is required".to_owned());
    }
    Ok(())
}

#[test]
fn inventory_is_complete_source_pinned_and_zero_unknown() {
    let inventory = artifact();
    validate_inventory(&inventory).unwrap_or_else(|error| panic!("{error}"));

    for pin in array(&inventory, "source_pins") {
        let path = text(pin, "path");
        let bytes = read_repo_bytes(path);
        let digest = hex::encode(Sha256::digest(&bytes));
        assert_eq!(digest, text(pin, "sha256"), "{path} source pin drifted");
        let line_count = read_repo_file(path).lines().count() as u64;
        assert_eq!(
            Some(line_count),
            pin.get("line_count").and_then(Value::as_u64),
            "{path} line count drifted"
        );
    }
}

#[test]
fn authority_registry_and_live_source_routes_are_truthful() {
    let inventory = artifact();
    let adr = read_repo_file(ADR_PATH);
    for marker in [
        "ADDITIVE_COEXISTENCE",
        "KEEP_UNTIL_PARITY",
        "KEEP_INCUMBENT",
        "CFG-GAP-01",
        "src/runtime/env_config.rs",
        "src/cli/atp_config.rs",
        "src/bin/atpd.rs",
        "src/bin/dependency_marginal_ledger.rs",
    ] {
        assert!(adr.contains(marker), "ADR must retain {marker}");
    }

    let registry = parse_repo_json(CAPABILITY_REGISTRY_PATH);
    let capability = array(&registry, "capabilities")
        .iter()
        .find(|row| row.get("capability_id").and_then(Value::as_str) == Some(CAPABILITY_ID))
        .expect("capability registry must retain CAP-CONFIG-TOML-JSON");
    assert_eq!(
        capability.get("cutover_state").and_then(Value::as_str),
        Some("KEEP_INCUMBENT")
    );
    assert_eq!(
        capability.get("disposition").and_then(Value::as_str),
        Some("KEEP_UNTIL_PARITY")
    );
    let stale_owners = string_set(capability, "source_owners");
    assert_eq!(
        stale_owners,
        ["src/bin/asupersync.rs", "src/config.rs"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        "CFG-GAP-01 must stay truthful until the registry owner repairs it"
    );

    let api_map = read_repo_file(API_SURFACE_MAP_PATH);
    assert!(api_map.contains("\"name\": \"config::ConfigLoader\""));
    assert!(api_map.contains("\"symbol\": \"runtime::RuntimeBuilder\""));

    let runtime = read_repo_file("src/runtime/env_config.rs");
    let builder = read_repo_file("src/runtime/builder.rs");
    let atp = read_repo_file("src/cli/atp_config.rs");
    let atpd = read_repo_file("src/bin/atpd.rs");
    let ledger = read_repo_file("src/bin/dependency_marginal_ledger.rs");
    let non_toml = read_repo_file("src/config.rs");
    assert!(runtime.contains("toml::from_str"));
    assert!(builder.contains("pub fn from_toml("));
    assert!(builder.contains("pub fn from_toml_str("));
    assert!(atp.contains("toml::from_str"));
    assert!(atp.contains("toml::to_string_pretty"));
    assert!(atpd.contains("let config: AtpdConfig = toml::from_str"));
    assert!(ledger.contains("toml::Value"));
    assert!(ledger.contains("toml::to_string_pretty"));
    assert!(
        !non_toml.contains("toml::"),
        "src/config.rs must remain explicitly classified as non-TOML"
    );

    let surface_paths: BTreeSet<String> = array(&inventory, "toml_surfaces")
        .iter()
        .flat_map(|row| {
            array(row, "source_paths")
                .iter()
                .map(|path| path.as_str().expect("source path").to_owned())
        })
        .collect();
    for expected in [
        "src/runtime/env_config.rs",
        "src/runtime/builder.rs",
        "src/cli/atp_config.rs",
        "src/cli/atp_command_tree.rs",
        "src/cli/first_run.rs",
        "src/cli/upgrade.rs",
        "src/bin/atpd.rs",
        "src/bin/dependency_marginal_ledger.rs",
    ] {
        assert!(
            surface_paths.contains(expected),
            "missing live source owner {expected}"
        );
    }
}

#[test]
fn generic_toml_grammar_corpus_matches_observed_parser_behavior() {
    let inventory = artifact();
    let generic_cases: Vec<&Value> = array(&inventory, "corpus_cases")
        .iter()
        .filter(|row| row.get("surface_id").and_then(Value::as_str) == Some("GENERIC"))
        .collect();
    assert_eq!(generic_cases.len(), 8);
    for row in generic_cases {
        let result = toml::from_str::<toml::Value>(text(row, "document"));
        match text(row, "expected") {
            "ACCEPT" => assert!(
                result.is_ok(),
                "{} unexpectedly rejected: {:?}",
                text(row, "case_id"),
                result.err()
            ),
            "REJECT" => assert!(
                result.is_err(),
                "{} unexpectedly accepted",
                text(row, "case_id")
            ),
            expected => panic!("unhandled generic expectation {expected}"),
        }
    }

    let commented = "# leading\nkey = \"value\" # trailing\n";
    let parsed: toml::Value = toml::from_str(commented).expect("comments must parse");
    let rendered = toml::to_string_pretty(&parsed).expect("generic value must serialize");
    assert_eq!(
        parsed.get("key").and_then(toml::Value::as_str),
        Some("value")
    );
    assert!(
        !rendered.contains('#'),
        "pretty writer must not claim comment retention"
    );
}

#[cfg(feature = "config-file")]
#[test]
fn runtime_toml_corpus_preserves_empty_full_unknown_error_and_boundary_cases() {
    use asupersync::runtime::RuntimeBuilder;
    use asupersync::runtime::env_config::parse_toml_str;

    let inventory = artifact();
    let corpus = array(&inventory, "corpus_cases");
    let empty = text(
        find_row(corpus, "case_id", "CFG-CORPUS-RUNTIME-EMPTY"),
        "document",
    );
    let empty_config = parse_toml_str(empty).expect("empty runtime TOML must parse");
    assert!(empty_config.scheduler.worker_threads.is_none());
    assert!(empty_config.blocking.max_threads.is_none());
    RuntimeBuilder::from_toml_str(empty).expect("empty runtime TOML must build an overlay");

    let full = text(
        find_row(corpus, "case_id", "CFG-CORPUS-RUNTIME-FULL"),
        "document",
    );
    let full_config = parse_toml_str(full).expect("full runtime TOML must parse");
    assert_eq!(full_config.scheduler.worker_threads, Some(8));
    assert_eq!(full_config.scheduler.poll_budget, Some(u32::MAX));
    assert_eq!(full_config.scheduler.governor_interval, Some(u32::MAX));
    assert_eq!(
        full_config.scheduler.adaptive_cancel_streak_epoch_steps,
        Some(u32::MAX)
    );
    assert_eq!(full_config.blocking.min_threads, Some(2));
    assert_eq!(full_config.blocking.max_threads, Some(32));
    RuntimeBuilder::from_toml_str(full).expect("full runtime TOML must apply");

    let unknown = text(
        find_row(corpus, "case_id", "CFG-CORPUS-RUNTIME-UNKNOWN"),
        "document",
    );
    let unknown_config = parse_toml_str(unknown).expect("unknown fields are currently ignored");
    assert_eq!(unknown_config.scheduler.worker_threads, Some(2));

    for case_id in [
        "CFG-CORPUS-RUNTIME-WRONG-TYPE",
        "CFG-CORPUS-RUNTIME-NUL-PREFIX",
    ] {
        let document = text(find_row(corpus, "case_id", case_id), "document");
        assert!(
            RuntimeBuilder::from_toml_str(document).is_err(),
            "{case_id} must fail"
        );
    }
}

#[cfg(feature = "cli")]
#[test]
fn atp_typed_toml_corpus_preserves_option_boundaries_roundtrip_and_errors() {
    use asupersync::cli::AtpConfig;
    use asupersync::cli::atp_config::{
        AtpInstallConfig, ConfigVersion, ProofRetentionPolicy, ReceiveSafetyPolicy,
    };
    use semver::Version;

    let inventory = artifact();
    let corpus = array(&inventory, "corpus_cases");

    let empty: AtpConfig = toml::from_str("").expect("empty ATP command layer must parse");
    assert!(empty.profile.is_none());
    assert!(empty.chunk_size.is_none());
    assert!(empty.verbose.is_none());

    let boundary = text(
        find_row(corpus, "case_id", "CFG-CORPUS-ATP-COMMAND-BOUNDARY"),
        "document",
    );
    let boundary: AtpConfig = toml::from_str(boundary).expect("signed TOML max must parse");
    assert_eq!(boundary.chunk_size, Some(i64::MAX as u64));
    assert_eq!(boundary.max_concurrent, Some(u32::MAX));

    let unsigned_max = text(
        find_row(corpus, "case_id", "CFG-CORPUS-ATP-COMMAND-FULL"),
        "document",
    );
    let unsigned_max: AtpConfig =
        toml::from_str(unsigned_max).expect("direct u64 target must accept u64::MAX");
    assert_eq!(unsigned_max.chunk_size, Some(u64::MAX));
    assert_eq!(unsigned_max.timeout, Some(u64::MAX));

    let unknown = text(
        find_row(corpus, "case_id", "CFG-CORPUS-ATP-COMMAND-UNKNOWN"),
        "document",
    );
    let unknown: AtpConfig = toml::from_str(unknown).expect("unknown ATP field is ignored");
    assert!(unknown.profile.is_some());
    assert!(
        toml::from_str::<AtpConfig>(text(
            find_row(corpus, "case_id", "CFG-CORPUS-ATP-COMMAND-BAD-ENUM"),
            "document"
        ))
        .is_err()
    );

    assert!(toml::from_str::<AtpInstallConfig>("").is_err());
    let install = AtpInstallConfig {
        schema_version: ConfigVersion::current(),
        version: Some(Version::parse("1.2.3").expect("valid semver")),
        identity_path: PathBuf::from("/tmp/asupersync/identity.key"),
        inbox_dir: PathBuf::from("/tmp/asupersync/inbox"),
        peer_dir: PathBuf::from("/tmp/asupersync/peers"),
        daemon_state_dir: PathBuf::from("/tmp/asupersync/state"),
        receive_safety_policy: ReceiveSafetyPolicy::KnownPeersOnly,
        proof_retention_policy: ProofRetentionPolicy::Days(30),
        enable_tailscale: true,
        allow_relays: false,
        logging_level: "info".to_owned(),
        service_platform: "linux".to_owned(),
        service_daemon_enabled: true,
        service_auto_start: false,
    };
    let rendered = toml::to_string_pretty(&install).expect("install config must serialize");
    let reparsed: AtpInstallConfig =
        toml::from_str(&rendered).expect("rendered install config must parse");
    assert_eq!(reparsed, install);
    let with_unknown = rendered.replacen(
        "\n[schema_version]",
        "\nfuture_security_mode = \"permissive\"\n\n[schema_version]",
        1,
    );
    let reparsed_unknown: AtpInstallConfig =
        toml::from_str(&with_unknown).expect("unknown install fields are currently ignored");
    assert_eq!(reparsed_unknown, install);
}

#[test]
fn precedence_io_errors_consumers_and_docs_remain_explicit() {
    let inventory = artifact();
    let runtime_precedence = find_row(
        array(&inventory, "precedence_contracts"),
        "precedence_id",
        "CFG-PRECEDENCE-RUNTIME",
    );
    assert_eq!(
        array(runtime_precedence, "low_to_high")
            .iter()
            .map(|entry| entry.as_str().expect("precedence entry"))
            .collect::<Vec<_>>(),
        vec![
            "RuntimeConfig::default",
            "RuntimeBuilder::from_toml or from_toml_str",
            "RuntimeBuilder::with_env_overrides when called after TOML construction",
            "later RuntimeBuilder programmatic setters",
        ]
    );

    let atp = read_repo_file("src/cli/atp_config.rs");
    assert!(atp.contains("self.load_daemon_policy()?;"));
    assert!(atp.contains("self.load_local_config()?;"));
    assert!(!atp.contains("self.load_user_config()?;"));
    assert!(atp.contains("if let Ok(config) = self.load_config_file"));
    assert!(atp.contains("fs::write(&validated_path, content)"));
    assert!(atp.contains("fs::write(path, content)"));

    let atpd = read_repo_file("src/bin/atpd.rs");
    assert!(atpd.contains("load_daemon_config(&cli.config).unwrap_or_else"));
    assert!(atpd.contains("Failed to load config"));
    assert!(atpd.contains("AtpdConfig::default()"));
    assert!(!atpd.contains("deny_unknown_fields"));

    let runtime = read_repo_file("src/runtime/env_config.rs");
    assert!(!runtime.contains("deny_unknown_fields"));
    assert!(runtime.contains("failed to parse TOML config"));
    assert!(runtime.contains("failed to read config file"));

    let doc = read_repo_file(DOC_PATH);
    let begin = doc.find(DOC_BEGIN).expect("doc begin marker");
    let end = doc.find(DOC_END).expect("doc end marker");
    assert!(begin < end);
    for marker in [
        "`CFG-TOML-RUNTIME`",
        "`CFG-TOML-ATP-COMMAND`",
        "`CFG-TOML-ATP-INSTALL`",
        "`CFG-TOML-ATPD`",
        "`CFG-TOML-DEPENDENCY-LEDGER`",
        "`CFG-NON-TOML-RAPTORQ`",
        "`CFG-GAP-16`",
        "zero `UNKNOWN`",
        "KEEP",
    ] {
        assert!(doc.contains(marker), "documentation must retain {marker}");
    }
}

#[test]
fn fail_closed_mutations_are_rejected() {
    let inventory = artifact();

    let mut dependency_exit = inventory.clone();
    dependency_exit["authority"]["dependency_exit_allowed"] = Value::Bool(true);
    assert!(validate_inventory(&dependency_exit).is_err());

    let mut unknown_state = inventory.clone();
    unknown_state["feature_profiles"][0]["evidence_state"] = Value::String("UNKNOWN".to_owned());
    assert!(validate_inventory(&unknown_state).is_err());

    let mut missing_surface = inventory.clone();
    missing_surface["toml_surfaces"]
        .as_array_mut()
        .expect("surfaces array")
        .pop();
    assert!(validate_inventory(&missing_surface).is_err());

    let mut wrong_field_count = inventory.clone();
    wrong_field_count["toml_surfaces"][0]["field_count"] = Value::from(13_u64);
    assert!(validate_inventory(&wrong_field_count).is_err());

    let mut missing_gap = inventory.clone();
    missing_gap["known_gaps"]
        .as_array_mut()
        .expect("gaps array")
        .pop();
    assert!(validate_inventory(&missing_gap).is_err());
}
