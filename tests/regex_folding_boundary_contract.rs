#[path = "../src/observability/regex_boundaries.rs"]
mod regex_boundaries;
#[path = "../src/observability/regex_semantics.rs"]
mod regex_semantics;
#[path = "../src/observability/regex_syntax.rs"]
mod regex_syntax;

use std::collections::BTreeSet;
use std::fs;

use regex::Regex;
use regex_boundaries::{
    BoundaryKind, FoldBoundaryErrorKind, FoldBoundaryLimits, LOCALE_SENSITIVE_FOLDS_SUPPORTED,
    MULTI_SCALAR_FOLDS_SUPPORTED, NORMALIZATION_PERFORMED, analyze,
};
use regex_semantics::{SemanticErrorKind, SemanticLimits};
use regex_syntax::{LexerLimits, ParserLimits};
use serde_json::Value;
use sha2::{Digest, Sha256};

const ARTIFACT_PATH: &str = "artifacts/regex_folding_boundary_contract_v1.json";
const DOC_PATH: &str = "docs/regex_folding_boundary_contract.md";
const SOURCE_PATH: &str = "src/observability/regex_boundaries.rs";
const SYNTAX_SOURCE_PATH: &str = "src/observability/regex_syntax.rs";
const SEMANTICS_SOURCE_PATH: &str = "src/observability/regex_semantics.rs";
const CARGO_PATH: &str = "Cargo.toml";
const FROZEN_SYNTAX_SHA256: &str =
    "2fbeae8fc1346d51cf5535930b750d0d69055d8923b3c6e8fcb3bf8ce25315b0";
const FROZEN_SEMANTICS_SHA256: &str =
    "bd762181da7620330a580152688af7684da371a9a32c144ef09ac5b5d0c2221a";

fn load_contract() -> Value {
    let text = fs::read_to_string(ARTIFACT_PATH).expect("fold/boundary artifact must be readable");
    serde_json::from_str(&text).expect("fold/boundary artifact must be valid JSON")
}

fn object<'value>(value: &'value Value, key: &str) -> &'value serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn array<'value>(value: &'value Value, key: &str) -> &'value [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn text<'value>(value: &'value Value, key: &str) -> &'value str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be text"))
}

fn number(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
}

fn boolean(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a boolean"))
}

fn sha256(path: &str) -> String {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("{path} must be readable: {error}"));
    hex::encode(Sha256::digest(bytes))
}

fn default_analyze(pattern: &str) -> regex_boundaries::FoldBoundaryAnalysis {
    analyze(
        pattern,
        LexerLimits::default(),
        ParserLimits::default(),
        SemanticLimits::default(),
        FoldBoundaryLimits::default(),
    )
    .unwrap_or_else(|error| panic!("fixture must analyze: {error}"))
}

#[test]
fn artifact_identity_and_fail_closed_decision_are_sealed() {
    let contract = load_contract();
    assert_eq!(number(&contract, "schema_version"), 1);
    assert_eq!(
        text(&contract, "artifact_id"),
        "regex-folding-boundary-contract-v1"
    );
    assert_eq!(text(&contract, "bead_id"), "asupersync-5z2scg.8.3.2.3");
    assert_eq!(text(&contract, "capability_id"), "CAP-REGEX-PRIVACY");
    assert_eq!(
        text(&contract, "semantics_id"),
        "ASUP-REGEX-FOLD-BOUNDARY-V1"
    );

    let decision = Value::Object(object(&contract, "decision").clone());
    assert_eq!(
        text(&decision, "disposition"),
        "STAGED_SIMPLE_FOLD_AND_BOUNDARY_SEMANTICS"
    );
    assert_eq!(
        text(&decision, "incumbent_state"),
        "RETAIN_REGEX_AND_REGEX_SYNTAX"
    );
    assert!(boolean(&decision, "r3_2_3_surface_complete"));
    assert!(!boolean(&decision, "cutover_eligible"));
    assert!(!boolean(&decision, "dependency_removal_authorized"));
    assert!(!boolean(&decision, "matcher_authorized"));
    assert!(!boolean(
        &decision,
        "terminal_cross_target_conformance_complete"
    ));

    let authority = Value::Object(object(&contract, "authority").clone());
    assert_eq!(text(&authority, "syntax_contract"), "ASUP-REGEX-SYNTAX-V1");
    assert_eq!(
        text(&authority, "character_semantics_contract"),
        "ASUP-REGEX-CHAR-SEMANTICS-V1"
    );
    assert_eq!(text(&authority, "retained_backend"), "regex-syntax@0.8.11");
    assert_eq!(text(&authority, "unicode_version"), "16.0.0");
    assert!(!boolean(&authority, "bytes_regex_consumer_reachable"));
    assert!(!boolean(&authority, "ambient_locale_used"));
    assert!(!boolean(&authority, "platform_tables_used"));
    assert!(!boolean(&authority, "normalization_used"));
}

#[test]
fn fold_boundary_variants_limits_diagnostics_and_corpus_are_complete() {
    let contract = load_contract();
    let fold = Value::Object(object(&contract, "fold_contract").clone());
    assert_eq!(text(&fold, "kind"), "UNICODE_SIMPLE_ONE_SCALAR");
    assert!(!boolean(&fold, "full_multi_scalar_folds_supported"));
    assert!(!boolean(&fold, "locale_sensitive_folds_supported"));
    assert!(!boolean(&fold, "normalization_performed"));
    assert!(!MULTI_SCALAR_FOLDS_SUPPORTED);
    assert!(!LOCALE_SENSITIVE_FOLDS_SUPPORTED);
    assert!(!NORMALIZATION_PERFORMED);

    let boundary = Value::Object(object(&contract, "boundary_contract").clone());
    assert_eq!(
        text(&boundary, "crlf_pair_policy"),
        "NEVER_MATCH_BETWEEN_CR_AND_LF"
    );
    let expected_variants = BTreeSet::from([
        "INPUT_START",
        "INPUT_END",
        "LINE_START_LF",
        "LINE_END_LF",
        "LINE_START_CRLF",
        "LINE_END_CRLF",
        "WORD_ASCII",
        "NOT_WORD_ASCII",
        "WORD_UNICODE",
        "NOT_WORD_UNICODE",
        "WORD_START_ASCII",
        "WORD_END_ASCII",
        "WORD_START_UNICODE",
        "WORD_END_UNICODE",
        "WORD_START_HALF_ASCII",
        "WORD_END_HALF_ASCII",
        "WORD_START_HALF_UNICODE",
        "WORD_END_HALF_UNICODE",
    ]);
    let actual_variants = array(&boundary, "variants")
        .iter()
        .map(|value| value.as_str().expect("variant must be text"))
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_variants, expected_variants);

    let limits = Value::Object(object(&contract, "limits").clone());
    for (key, expected) in [
        ("max_fold_atoms", 1_048_576),
        ("max_ranges_per_fold", 4_096),
        ("max_total_fold_ranges", 1_048_576),
        ("max_boundary_assertions", 1_048_576),
        ("backend_nesting_limit", 250),
    ] {
        assert_eq!(number(&limits, key), expected);
    }

    let diagnostic_codes = array(&contract, "diagnostics")
        .iter()
        .map(|row| text(row, "code"))
        .collect::<BTreeSet<_>>();
    let expected_codes = BTreeSet::from([
        "RGX-FB-E001",
        "RGX-FB-E002",
        "RGX-FB-E003",
        "RGX-FB-E004",
        "RGX-FB-E005",
        "RGX-FB-E006",
        "RGX-FB-E007",
        "RGX-FB-EVAL-E001",
        "RGX-FB-EVAL-E002",
    ]);
    assert_eq!(diagnostic_codes, expected_codes);

    let cases = array(&contract, "semantic_cases");
    assert_eq!(cases.len(), 20);
    let actual_case_ids = cases
        .iter()
        .map(|row| text(row, "case_id"))
        .collect::<BTreeSet<_>>();
    let expected_case_ids = (1..=20)
        .map(|index| format!("RGX-R323-C{index:03}"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_case_ids,
        expected_case_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
    );

    let r1_rows = array(&contract, "r1_rows")
        .iter()
        .map(|row| text(row, "case_id"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        r1_rows,
        BTreeSet::from([
            "RGX-SYN-006",
            "RGX-SYN-007",
            "RGX-SYN-009",
            "RGX-SYN-010",
            "RGX-SYN-019",
            "RGX-SYN-020",
            "RGX-SYN-023",
        ])
    );
}

#[test]
fn source_hashes_dependency_and_private_wiring_preserve_predecessor_receipts() {
    let contract = load_contract();
    let source = Value::Object(object(&contract, "source").clone());
    assert_eq!(text(&source, "path"), SOURCE_PATH);
    assert_eq!(text(&source, "sha256"), sha256(SOURCE_PATH));
    assert_eq!(text(&source, "visibility"), "pub(crate)");
    assert_eq!(text(&source, "feature"), "metrics");
    assert!(!boolean(&source, "public_api_added"));
    assert!(!boolean(&source, "unsafe_code_added"));

    assert_eq!(sha256(SYNTAX_SOURCE_PATH), FROZEN_SYNTAX_SHA256);
    assert_eq!(sha256(SEMANTICS_SOURCE_PATH), FROZEN_SEMANTICS_SHA256);
    let authority = Value::Object(object(&contract, "authority").clone());
    assert_eq!(
        text(&authority, "syntax_source_sha256"),
        FROZEN_SYNTAX_SHA256
    );
    assert_eq!(
        text(&authority, "character_semantics_source_sha256"),
        FROZEN_SEMANTICS_SHA256
    );

    let cargo = fs::read_to_string(CARGO_PATH).expect("Cargo.toml must be readable");
    assert!(cargo.contains(
        "retained-regex-syntax = { package = \"regex-syntax\", version = \"=0.8.11\", optional = true }"
    ));
    assert!(cargo.contains("\"dep:retained-regex-syntax\""));
    let module = fs::read_to_string("src/observability/mod.rs").expect("module root readable");
    assert!(module.contains("pub(crate) mod regex_boundaries;"));
}

#[test]
fn docs_commands_and_no_claim_boundaries_are_discoverable() {
    let docs = fs::read_to_string(DOC_PATH).expect("fold/boundary docs must be readable");
    for marker in [
        "<!-- BEGIN REGEX FOLDING BOUNDARY CONTRACT -->",
        "STAGED_SIMPLE_FOLD_AND_BOUNDARY_SEMANTICS",
        "UNICODE_SIMPLE_ONE_SCALAR",
        "CRLF-aware line boundaries",
        "RGX-FB-E003",
        "--test regex_folding_boundary_contract",
        "--all-targets --keep-going -- -D warnings",
        "No local Cargo fallback is approved.",
        "j-29947326818680928",
        "68 passed, 0 failed",
        "gracefully cancelled after 261 seconds",
        "R3.2.4 retains sole authority",
        "<!-- END REGEX FOLDING BOUNDARY CONTRACT -->",
    ] {
        assert!(docs.contains(marker), "missing docs marker: {marker}");
    }

    let contract = load_contract();
    let proof = object(&contract, "proof");
    for (lane, build_id) in [
        ("warning_denied_lib_check", 29_947_326_818_680_927),
        ("focused_contract_test", 29_947_326_818_680_928),
        ("focused_clippy", 29_947_326_818_680_926),
    ] {
        let receipt = Value::Object(
            proof
                .get(lane)
                .and_then(Value::as_object)
                .unwrap_or_else(|| panic!("{lane} proof receipt must be an object"))
                .clone(),
        );
        assert_eq!(text(&receipt, "state"), "PASSED");
        assert_eq!(number(&receipt, "build_id"), build_id);
        assert_eq!(number(&receipt, "exit_code"), 0);
        assert!(!boolean(&receipt, "local_fallback_used"));
    }
    let focused = Value::Object(
        proof
            .get("focused_contract_test")
            .and_then(Value::as_object)
            .expect("focused contract receipt must be an object")
            .clone(),
    );
    assert_eq!(number(&focused, "tests_passed"), 68);
    assert_eq!(number(&focused, "tests_failed"), 0);
    let broad = Value::Object(
        proof
            .get("broad_all_targets_clippy")
            .and_then(Value::as_object)
            .expect("broad Clippy receipt must be an object")
            .clone(),
    );
    assert_eq!(text(&broad, "state"), "BLOCKED_STALE_PROGRESS_CANCELLED");
    assert_eq!(number(&broad, "build_id"), 29_947_326_818_680_929);
    assert!(!boolean(&broad, "heartbeat_stale"));
    assert_eq!(number(&broad, "progress_age_at_cancel_seconds"), 261);
    assert!(boolean(&broad, "graceful_cancel"));
    assert!(!boolean(&broad, "terminal_success_claimed"));
    assert!(!boolean(&broad, "local_fallback_used"));

    let no_claims = array(&contract, "no_claims")
        .iter()
        .map(|value| value.as_str().expect("no-claim row must be text"))
        .collect::<Vec<_>>()
        .join("\n");
    for marker in [
        "no regex or regex-syntax removal authorization",
        "no candidate production wiring",
        "no terminal Unicode byte or cross-target conformance",
        "no performance improvement or no-regression claim",
        "no broad workspace health or release-readiness claim",
        "no locale-sensitive or full multi-scalar folding",
        "no normalization",
        "no local Cargo fallback approval",
    ] {
        assert!(no_claims.contains(marker), "missing no-claim: {marker}");
    }
}

#[test]
fn fold_goldens_agree_with_incumbent_single_scalar_language() {
    let cases: &[(&str, &[char])] = &[
        ("(?i:a)", &['a', 'A']),
        ("(?i:σ)", &['σ', 'Σ', 'ς']),
        ("(?i:k)", &['k', 'K', '\u{212A}']),
        ("(?i:[a-c])", &['a', 'A', 'b', 'B', 'c', 'C']),
        ("(?i-u:a)", &['a', 'A']),
        ("(?i-u:é)", &['é']),
    ];
    for (pattern, expected) in cases {
        let analysis = default_analyze(pattern);
        assert_eq!(analysis.folds.len(), 1, "fixture: {pattern}");
        let incumbent =
            Regex::new(&format!(r"\A(?:{pattern})\z")).expect("incumbent pattern must compile");
        for scalar in *expected {
            assert!(
                analysis.folds[0].folded.matches_single_scalar(*scalar),
                "candidate omitted {scalar:?} for {pattern}"
            );
            assert!(
                incumbent.is_match(&scalar.to_string()),
                "incumbent omitted {scalar:?} for {pattern}"
            );
        }
    }

    for (pattern, rejected) in [("(?i-u:k)", '\u{212A}'), ("(?i-u:é)", 'É'), ("(?i:ß)", 's')] {
        let analysis = default_analyze(pattern);
        let incumbent =
            Regex::new(&format!(r"\A(?:{pattern})\z")).expect("incumbent pattern must compile");
        assert!(!analysis.folds[0].folded.matches_single_scalar(rejected));
        assert!(!incumbent.is_match(&rejected.to_string()));
    }
    assert!(
        !Regex::new(r"\A(?i:ß)\z")
            .expect("sharp-s incumbent pattern")
            .is_match("ss")
    );
}

#[test]
fn every_boundary_truth_table_agrees_with_incumbent_corpus() {
    let variants = [
        (BoundaryKind::InputStart, r"\A"),
        (BoundaryKind::InputEnd, r"\z"),
        (BoundaryKind::LineStartLf, r"(?m:^)"),
        (BoundaryKind::LineEndLf, r"(?m:$)"),
        (BoundaryKind::LineStartCrlf, r"(?mR:^)"),
        (BoundaryKind::LineEndCrlf, r"(?mR:$)"),
        (BoundaryKind::WordAscii, r"(?-u:\b)"),
        (BoundaryKind::NotWordAscii, r"(?-u:\B)"),
        (BoundaryKind::WordUnicode, r"\b"),
        (BoundaryKind::NotWordUnicode, r"\B"),
        (BoundaryKind::WordStartAscii, r"(?-u:\b{start})"),
        (BoundaryKind::WordEndAscii, r"(?-u:\b{end})"),
        (BoundaryKind::WordStartUnicode, r"\b{start}"),
        (BoundaryKind::WordEndUnicode, r"\b{end}"),
        (BoundaryKind::WordStartHalfAscii, r"(?-u:\b{start-half})"),
        (BoundaryKind::WordEndHalfAscii, r"(?-u:\b{end-half})"),
        (BoundaryKind::WordStartHalfUnicode, r"\b{start-half}"),
        (BoundaryKind::WordEndHalfUnicode, r"\b{end-half}"),
    ];
    let haystacks = [
        "",
        "a",
        " a ",
        "$a",
        "κόσμος",
        " κόσμος ",
        " \u{301} ",
        "a\nb",
        "a\r\nb",
        "a\rb",
        "💩_β-9",
    ];
    for (kind, pattern) in variants {
        let incumbent = Regex::new(pattern).expect("incumbent boundary pattern must compile");
        for haystack in haystacks {
            let offsets = haystack
                .char_indices()
                .map(|(offset, _)| offset)
                .chain(core::iter::once(haystack.len()));
            for offset in offsets {
                let expected = incumbent
                    .find_at(haystack, offset)
                    .is_some_and(|found| found.start() == offset);
                let actual = kind
                    .is_match(haystack, offset)
                    .expect("corpus offset is a UTF-8 boundary");
                assert_eq!(
                    actual, expected,
                    "boundary drift: {kind:?}, {pattern}, {haystack:?}, offset {offset}"
                );
            }
        }
    }
}

#[test]
fn accounting_and_private_source_canary_fail_closed() {
    let pattern = r"(?i:σ)(?i-u:a)\b(?-u:\B)(?mR:^x$)\A\z";
    let analysis = default_analyze(pattern);
    assert!(analysis.invariants_hold(
        pattern,
        SemanticLimits::default(),
        FoldBoundaryLimits::default()
    ));
    assert_eq!(analysis.resources.case_insensitive_atoms, 2);
    assert_eq!(analysis.resources.boundary_assertions, 6);

    let secret = "PRIVATE_FOLD_PROPERTY_CANARY";
    let private_pattern = format!(r"(?i:\p{{{secret}}})");
    let error = analyze(
        &private_pattern,
        LexerLimits::default(),
        ParserLimits::default(),
        SemanticLimits::default(),
        FoldBoundaryLimits::default(),
    )
    .expect_err("unknown property must fail closed");
    assert_eq!(
        error.kind,
        FoldBoundaryErrorKind::CharacterSemantics(SemanticErrorKind::UnknownUnicodeProperty)
    );
    let rendered = error.to_string();
    assert!(rendered.starts_with("[RGX-SEM-E001]"));
    assert!(!rendered.contains(secret));
    assert!(!rendered.contains(&private_pattern));
}
