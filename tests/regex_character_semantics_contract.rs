#[path = "../src/observability/regex_semantics.rs"]
mod regex_semantics;
#[path = "../src/observability/regex_syntax.rs"]
mod regex_syntax;

use std::collections::BTreeSet;
use std::fs;

use regex_character_semantics_contract_support::{
    ARTIFACT_PATH, CARGO_LOCK_PATH, CARGO_PATH, DOC_PATH, SOURCE_PATH, validate_contract,
};
use regex_semantics::{ClassAlphabet, SemanticErrorKind, SemanticLimits, analyze};
use regex_syntax::{LexerLimits, ParserLimits};
use serde_json::Value;
use sha2::{Digest, Sha256};

mod regex_character_semantics_contract_support {
    use super::*;

    pub const ARTIFACT_PATH: &str = "artifacts/regex_character_semantics_contract_v1.json";
    pub const SOURCE_PATH: &str = "src/observability/regex_semantics.rs";
    pub const DOC_PATH: &str = "docs/regex_character_semantics_contract.md";
    pub const CARGO_PATH: &str = "Cargo.toml";
    pub const CARGO_LOCK_PATH: &str = "Cargo.lock";

    fn object<'value>(
        value: &'value Value,
        key: &str,
    ) -> Result<&'value serde_json::Map<String, Value>, String> {
        value
            .get(key)
            .and_then(Value::as_object)
            .ok_or_else(|| format!("{key} must be an object"))
    }

    fn array<'value>(value: &'value Value, key: &str) -> Result<&'value [Value], String> {
        value
            .get(key)
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .ok_or_else(|| format!("{key} must be an array"))
    }

    fn text<'value>(value: &'value Value, key: &str) -> Result<&'value str, String> {
        value
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{key} must be text"))
    }

    fn number(value: &Value, key: &str) -> Result<u64, String> {
        value
            .get(key)
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("{key} must be an unsigned integer"))
    }

    fn boolean(value: &Value, key: &str) -> Result<bool, String> {
        value
            .get(key)
            .and_then(Value::as_bool)
            .ok_or_else(|| format!("{key} must be a boolean"))
    }

    pub fn validate_contract(contract: &Value) -> Result<(), String> {
        if number(contract, "schema_version")? != 1
            || text(contract, "artifact_id")? != "regex-character-semantics-contract-v1"
            || text(contract, "bead_id")? != "asupersync-5z2scg.8.3.2.2"
            || text(contract, "capability_id")? != "CAP-REGEX-PRIVACY"
            || text(contract, "semantics_id")? != "ASUP-REGEX-CHAR-SEMANTICS-V1"
        {
            return Err("identity fields drifted".to_owned());
        }

        let decision = object(contract, "decision")?;
        if text(&Value::Object(decision.clone()), "disposition")? != "STAGED_RETAINED_TABLE_BACKEND"
            || text(&Value::Object(decision.clone()), "incumbent_state")?
                != "RETAIN_REGEX_AND_REGEX_SYNTAX"
            || !boolean(&Value::Object(decision.clone()), "r3_2_2_surface_complete")?
            || boolean(&Value::Object(decision.clone()), "cutover_eligible")?
            || boolean(
                &Value::Object(decision.clone()),
                "dependency_removal_authorized",
            )?
            || boolean(
                &Value::Object(decision.clone()),
                "owned_unicode_tables_authorized",
            )?
        {
            return Err("decision must remain staged and fail closed".to_owned());
        }

        let authority = object(contract, "authority")?;
        let authority_value = Value::Object(authority.clone());
        if text(&authority_value, "syntax_contract")? != "ASUP-REGEX-SYNTAX-V1"
            || text(&authority_value, "unicode_version")? != "16.0.0"
            || text(&authority_value, "consumer_input_type")? != "&str pattern and &str haystack"
            || boolean(&authority_value, "bytes_regex_consumer_reachable")?
            || boolean(&authority_value, "ambient_locale_used")?
            || boolean(&authority_value, "platform_tables_used")?
        {
            return Err("authority or input contract drifted".to_owned());
        }

        let backend = object(contract, "retained_backend")?;
        let backend_value = Value::Object(backend.clone());
        if text(&backend_value, "dependency_alias")? != "retained-regex-syntax"
            || text(&backend_value, "package")? != "regex-syntax"
            || text(&backend_value, "version")? != "0.8.11"
            || text(&backend_value, "version_requirement")? != "=0.8.11"
            || text(&backend_value, "unicode_version")? != "16.0.0"
            || !boolean(&backend_value, "cargo_optional")?
            || !boolean(&backend_value, "already_in_incumbent_graph")?
            || number(&backend_value, "new_unique_packages")? != 0
            || boolean(&backend_value, "table_copy_added")?
            || boolean(&backend_value, "build_script_added")?
            || boolean(&backend_value, "proc_macro_added")?
            || boolean(&backend_value, "native_code_added")?
        {
            return Err("retained backend contract drifted".to_owned());
        }
        let expected_features = BTreeSet::from([
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment",
        ]);
        let actual_features = array(&backend_value, "default_table_features")?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| "table feature must be text".to_owned())
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if actual_features != expected_features {
            return Err("retained Unicode feature bundle drifted".to_owned());
        }

        let alphabet = object(contract, "alphabet_contract")?;
        let alphabet_value = Value::Object(alphabet.clone());
        if text(&alphabet_value, "default_alphabet")? != "UNICODE_SCALAR"
            || text(&alphabet_value, "surrogate_policy")? != "EXCLUDED_NOT_A_SCALAR"
            || text(&alphabet_value, "noncharacter_policy")? != "ACCEPT_AS_SCALAR"
            || text(&alphabet_value, "unicode_disabled_alphabet")? != "UTF8_SAFE_BYTE"
            || number(&alphabet_value, "unicode_disabled_byte_max")? != 127
            || text(&alphabet_value, "invalid_nonempty_utf8_match_policy")? != "REJECT"
            || text(&alphabet_value, "unicode_property_in_byte_mode_policy")? != "REJECT"
        {
            return Err("alphabet contract drifted".to_owned());
        }

        let representation = object(contract, "canonical_representation")?;
        let representation_value = Value::Object(representation.clone());
        if text(&representation_value, "range_endpoints")? != "inclusive"
            || text(&representation_value, "ordering")? != "ascending"
            || text(&representation_value, "overlap")? != "forbidden"
            || text(&representation_value, "adjacency")? != "merged"
            || text(&representation_value, "membership_lookup")? != "binary_search"
            || !boolean(&representation_value, "empty_class_allowed")?
            || !boolean(&representation_value, "checked_aggregate_accounting")?
        {
            return Err("canonical representation drifted".to_owned());
        }
        let expected_operations = BTreeSet::from([
            "difference",
            "intersection",
            "negation",
            "range",
            "symmetric_difference",
            "union",
        ]);
        let actual_operations = array(&representation_value, "set_operations")?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| "set operation must be text".to_owned())
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if actual_operations != expected_operations {
            return Err("set-operation surface drifted".to_owned());
        }

        let limits = object(contract, "limits")?;
        let limits_value = Value::Object(limits.clone());
        for (key, expected) in [
            ("max_pattern_bytes", 1_048_576),
            ("max_syntax_tokens", 1_048_576),
            ("max_syntax_nodes", 1_048_576),
            ("max_syntax_nesting", 250),
            ("max_semantic_atoms", 1_048_576),
            ("max_ranges_per_class", 4_096),
            ("max_total_ranges", 1_048_576),
            ("backend_nesting_limit", 250),
        ] {
            if number(&limits_value, key)? != expected {
                return Err(format!("{key} budget drifted"));
            }
        }

        let diagnostic_codes = array(contract, "diagnostics")?
            .iter()
            .map(|row| text(row, "code"))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let expected_codes = (1..=9)
            .map(|index| format!("RGX-SEM-E{index:03}"))
            .collect::<BTreeSet<_>>();
        if diagnostic_codes
            != expected_codes
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
        {
            return Err("semantic diagnostic registry drifted".to_owned());
        }

        let semantic_cases = array(contract, "semantic_cases")?;
        if semantic_cases.len() != 15 {
            return Err("semantic corpus must contain exactly 15 cases".to_owned());
        }
        let case_ids = semantic_cases
            .iter()
            .map(|row| text(row, "case_id"))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let expected_case_ids = (1..=15)
            .map(|index| format!("RGX-R322-C{index:03}"))
            .collect::<BTreeSet<_>>();
        if case_ids
            != expected_case_ids
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
        {
            return Err("semantic case IDs must be complete and unique".to_owned());
        }

        let r1_rows = array(contract, "r1_rows")?;
        let actual_r1 = r1_rows
            .iter()
            .map(|row| text(row, "case_id"))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let expected_r1 = BTreeSet::from([
            "RGX-SYN-013",
            "RGX-SYN-014",
            "RGX-SYN-015",
            "RGX-SYN-016",
            "RGX-SYN-017",
            "RGX-SYN-018",
            "RGX-SYN-021",
            "RGX-SYN-024",
        ]);
        if actual_r1 != expected_r1 {
            return Err("R1 semantic row join drifted".to_owned());
        }

        let evidence = object(contract, "test_evidence")?;
        let evidence_value = Value::Object(evidence.clone());
        if number(&evidence_value, "inline_unit_tests")? != 12
            || number(&evidence_value, "property_lanes")? != 2
            || number(&evidence_value, "property_cases_per_lane")? != 256
            || number(&evidence_value, "generated_property_cases")? != 512
            || text(&evidence_value, "downstream_no_mock_e2e_owner")? != "asupersync-5z2scg.8.3.2.4"
        {
            return Err("test evidence accounting drifted".to_owned());
        }

        let no_claims = array(contract, "no_claims")?;
        let no_claim_text = no_claims
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| "no-claim row must be text".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?
            .join("\n");
        for required in [
            "does not authorize removing regex or regex-syntax",
            "does not claim owned Unicode tables",
            "does not claim case-insensitive folding parity",
            "does not claim word, line, or input boundary parity",
            "does not compile or execute a matcher",
            "does not prove terminal Unicode or byte conformance owned by R3.2.4",
            "does not approve local Cargo fallback",
        ] {
            if !no_claim_text.contains(required) {
                return Err(format!("missing no-claim boundary: {required}"));
            }
        }
        Ok(())
    }
}

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("read {path}: {error}"))
}

fn contract() -> Value {
    serde_json::from_str(&read(ARTIFACT_PATH))
        .unwrap_or_else(|error| panic!("parse {ARTIFACT_PATH}: {error}"))
}

fn semantic_behavior(pattern: &str) -> Result<regex_semantics::SemanticAnalysis, String> {
    analyze(
        pattern,
        LexerLimits::default(),
        ParserLimits::default(),
        SemanticLimits::default(),
    )
    .map_err(|error| error.to_string())
}

#[test]
fn semantic_behavior_matches_unicode_and_set_goldens() {
    let analysis = semantic_behavior(r"[\pL&&\p{Greek}]").expect("Greek intersection must compile");
    assert!(analysis.invariants_hold(r"[\pL&&\p{Greek}]", SemanticLimits::default()));
    let class = analysis.classes.first().expect("one canonical class");
    assert_eq!(class.alphabet(), ClassAlphabet::UnicodeScalar);
    assert!(class.contains_scalar('κ'));
    assert!(!class.contains_scalar('A'));

    let consonants = semantic_behavior("[a-z&&[^aeiou]]").expect("nested class must compile");
    let class = consonants.classes.first().expect("one consonant class");
    assert!(class.contains_scalar('b'));
    assert!(!class.contains_scalar('a'));
}

#[test]
fn semantic_behavior_preserves_valid_utf8_and_rejects_invalid_bytes() {
    let valid = semantic_behavior(r"(?-u:\xC2\xA0)").expect("complete UTF-8 sequence must compile");
    assert_eq!(valid.resources.byte_scopes_validated, 1);

    let invalid = analyze(
        r"(?-u:\xFF)",
        LexerLimits::default(),
        ParserLimits::default(),
        SemanticLimits::default(),
    )
    .expect_err("isolated invalid byte must fail");
    assert_eq!(invalid.kind, SemanticErrorKind::InvalidUtf8Boundary);

    let property = analyze(
        r"(?-u:\pL)",
        LexerLimits::default(),
        ParserLimits::default(),
        SemanticLimits::default(),
    )
    .expect_err("Unicode property in byte mode must fail");
    assert_eq!(property.kind, SemanticErrorKind::UnicodePropertyInByteMode);
}

#[test]
fn contract_schema_and_source_digests_are_exact() {
    let value = contract();
    validate_contract(&value).expect("character semantic contract must validate");

    let source = fs::read(SOURCE_PATH).expect("semantic source must exist");
    let source_digest = hex::encode(Sha256::digest(&source));
    assert_eq!(
        value["source"]["sha256"].as_str(),
        Some(source_digest.as_str())
    );

    let syntax = fs::read("src/observability/regex_syntax.rs").expect("syntax source must exist");
    let syntax_digest = hex::encode(Sha256::digest(&syntax));
    assert_eq!(
        value["authority"]["syntax_source_sha256"].as_str(),
        Some(syntax_digest.as_str())
    );
}

#[test]
fn dependency_edge_is_exact_optional_and_already_locked() {
    let cargo = read(CARGO_PATH);
    assert!(cargo.contains("\"dep:retained-regex-syntax\""));
    assert!(cargo.contains(
        "retained-regex-syntax = { package = \"regex-syntax\", version = \"=0.8.11\", optional = true }"
    ));

    let lock = read(CARGO_LOCK_PATH);
    assert!(lock.contains("name = \"regex-syntax\"\nversion = \"0.8.11\""));
    let root_package = format!(
        "name = \"asupersync\"\nversion = \"{}\"",
        env!("CARGO_PKG_VERSION")
    );
    let root = lock
        .split("[[package]]")
        .find(|package| package.contains(&root_package))
        .expect("root package must exist");
    assert!(root.contains("\"regex-syntax\""));
}

#[test]
fn documentation_pins_decision_limits_replay_and_no_claims() {
    let docs = read(DOC_PATH);
    for marker in [
        "<!-- BEGIN REGEX CHARACTER SEMANTICS CONTRACT -->",
        "`STAGED_RETAINED_TABLE_BACKEND`",
        "`UTF8_SAFE_BYTE`",
        "`RGX-SEM-E001`",
        "`RGX-SEM-E003`",
        "ranges in one class",
        "`--all-targets --keep-going -- -D warnings`",
        "No local Cargo fallback is approved.",
        "does not authorize removing `regex` or `regex-syntax`",
        "R3.2.4 owns the sole",
        "<!-- END REGEX CHARACTER SEMANTICS CONTRACT -->",
    ] {
        assert!(docs.contains(marker), "missing docs marker: {marker}");
    }
}

#[test]
fn contract_mutations_fail_closed() {
    let base = contract();
    let mut mutations = Vec::new();

    let mut cutover = base.clone();
    cutover["decision"]["cutover_eligible"] = Value::Bool(true);
    mutations.push(cutover);

    let mut byte_max = base.clone();
    byte_max["alphabet_contract"]["unicode_disabled_byte_max"] = Value::from(255);
    mutations.push(byte_max);

    let mut range_budget = base.clone();
    range_budget["limits"]["max_ranges_per_class"] = Value::from(4_097);
    mutations.push(range_budget);

    let mut missing_case = base.clone();
    missing_case["semantic_cases"]
        .as_array_mut()
        .expect("semantic cases must be an array")
        .pop();
    mutations.push(missing_case);

    let mut missing_boundary = base;
    missing_boundary["no_claims"]
        .as_array_mut()
        .expect("no claims must be an array")
        .retain(|row| row.as_str() != Some("does not authorize removing regex or regex-syntax"));
    mutations.push(missing_boundary);

    for mutation in mutations {
        assert!(validate_contract(&mutation).is_err());
    }
}
