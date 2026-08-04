#[path = "../src/observability/regex_boundaries.rs"]
mod regex_boundaries;
#[path = "../src/observability/regex_semantics.rs"]
mod regex_semantics;
#[path = "../src/observability/regex_syntax.rs"]
mod regex_syntax;

use std::collections::BTreeSet;
use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};

use regex::Regex;
use regex_boundaries::{
    BoundaryEvalErrorKind, BoundaryKind, FoldBoundaryErrorKind, FoldBoundaryLimits,
};
use regex_semantics::{SemanticErrorKind, SemanticLimits};
use regex_syntax::{LexerLimits, ParserLimits};
use serde_json::Value;
use sha2::{Digest, Sha256};

const ARTIFACT_PATH: &str = "artifacts/regex_semantic_terminal_receipt_v1.json";
const DOC_PATH: &str = "docs/regex_semantic_terminal_receipt.md";
const SYNTAX_PATH: &str = "src/observability/regex_syntax.rs";
const SEMANTICS_PATH: &str = "src/observability/regex_semantics.rs";
const BOUNDARIES_PATH: &str = "src/observability/regex_boundaries.rs";
const GENERATED_SEED: u64 = 0x5A2C_0324_D15C_A11E;

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("read {path}: {error}"))
}

fn contract() -> Value {
    serde_json::from_str(&read(ARTIFACT_PATH))
        .unwrap_or_else(|error| panic!("parse {ARTIFACT_PATH}: {error}"))
}

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

fn sha256(path: &str) -> String {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {path}: {error}"));
    hex::encode(Sha256::digest(bytes))
}

fn terminal_validate(value: &Value) -> Result<(), String> {
    if number(value, "schema_version")? != 1
        || text(value, "artifact_id")? != "regex-semantic-terminal-receipt-v1"
        || text(value, "bead_id")? != "asupersync-5z2scg.8.3.2.4"
        || text(value, "capability_id")? != "CAP-REGEX-PRIVACY"
        || text(value, "terminal_id")? != "ASUP-REGEX-SEMANTICS-TERMINAL-V1"
    {
        return Err("identity drifted".to_owned());
    }

    let decision = Value::Object(object(value, "decision")?.clone());
    if text(&decision, "disposition")? != "KEEP_INCUMBENT_DEFER"
        || text(&decision, "incumbent_state")? != "RETAIN_REGEX_AND_REGEX_SYNTAX"
        || text(&decision, "semantic_rows")? != "SAME_WITH_EXPLICIT_KEEP_DEFER"
        || !boolean(&decision, "r3_2_semantic_surface_complete")?
        || !boolean(&decision, "compiler_experimentation_authorized")?
        || !boolean(&decision, "compiler_must_retain_pinned_semantics")?
        || boolean(&decision, "production_cutover_eligible")?
        || boolean(&decision, "dependency_removal_authorized")?
        || boolean(&decision, "owned_unicode_tables_authorized")?
        || boolean(&decision, "isolated_binary_delta_complete")?
        || boolean(&decision, "cross_target_terminal_complete")?
    {
        return Err("terminal decision must fail closed".to_owned());
    }

    let predecessors = array(value, "predecessors")?;
    let expected_predecessors = [
        (
            "artifacts/regex_unicode_table_contract_v1.json",
            "61e38fe79120fc9e79b7f55c3142f92ce0032bfed0ced8742d1063675790d24a",
        ),
        (
            "artifacts/regex_character_semantics_contract_v1.json",
            "06c4c42c32e1f875fc0219be202744653af9e7f81227a1f65fc782fb7f680d6d",
        ),
        (
            "artifacts/regex_folding_boundary_contract_v1.json",
            "c462ddc3903335e7895ef54e1a1a4085c814cb5881a4f2fdcb523483cb45478d",
        ),
    ];
    if predecessors.len() != expected_predecessors.len() {
        return Err("predecessor count drifted".to_owned());
    }
    for (row, (path, digest)) in predecessors.iter().zip(expected_predecessors) {
        if text(row, "path")? != path || text(row, "sha256")? != digest {
            return Err(format!("predecessor drifted: {path}"));
        }
    }

    let corpus = Value::Object(object(value, "conformance_corpus")?.clone());
    if text(&corpus, "accepted_row_policy")? != "SAME_OR_BETTER_ELSE_KEEP_DEFER"
        || number(&corpus, "official_vector_count")? != 20
        || number(&corpus, "generated_pattern_cases")? != 1_024
        || number(&corpus, "generated_word_pair_cases")? != 121
        || array(&corpus, "minimized_failures")?.len() != 1
        || !array(&corpus, "unresolved_semantic_drifts")?.is_empty()
    {
        return Err("corpus metadata drifted".to_owned());
    }
    let rows = array(&corpus, "rows")?;
    if rows.len() != 20
        || rows.iter().any(|row| {
            !matches!(
                row.get("result").and_then(Value::as_str),
                Some("SAME" | "BETTER" | "KEEP_DEFER")
            )
        })
    {
        return Err("accepted conformance row regressed".to_owned());
    }

    let targets = array(value, "target_matrix")?;
    if targets.len() != 3
        || text(&targets[1], "execution_state")? != "NOT_EXECUTED"
        || text(&targets[2], "execution_state")? != "NOT_EXECUTED"
        || text(&targets[1], "decision")? != "KEEP_DEFER"
        || text(&targets[2], "decision")? != "KEEP_DEFER"
    {
        return Err("cross-target matrix must remain fail closed".to_owned());
    }

    let no_claims = array(value, "no_claims")?
        .iter()
        .map(|row| {
            row.as_str()
                .ok_or_else(|| "no-claim row must be text".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    for marker in [
        "no regex or regex-syntax removal authorization",
        "no candidate production wiring or matcher execution",
        "no owned Unicode table authorization",
        "no isolated release artifact size delta",
        "no complete ARM or WASM execution evidence",
        "no performance improvement or no-regression claim",
        "no broad workspace health or release-readiness claim",
        "no local Cargo fallback approval",
    ] {
        if !no_claims.contains(marker) {
            return Err(format!("missing no-claim: {marker}"));
        }
    }
    Ok(())
}

fn semantic(pattern: &str) -> regex_semantics::SemanticAnalysis {
    regex_semantics::analyze(
        pattern,
        LexerLimits::default(),
        ParserLimits::default(),
        SemanticLimits::default(),
    )
    .unwrap_or_else(|error| panic!("semantic fixture {pattern:?}: {error}"))
}

fn folded(pattern: &str) -> regex_boundaries::FoldBoundaryAnalysis {
    regex_boundaries::analyze(
        pattern,
        LexerLimits::default(),
        ParserLimits::default(),
        SemanticLimits::default(),
        FoldBoundaryLimits::default(),
    )
    .unwrap_or_else(|error| panic!("fold/boundary fixture {pattern:?}: {error}"))
}

fn class_matches(pattern: &str, scalar: char) -> bool {
    let analysis = semantic(pattern);
    assert_eq!(analysis.classes.len(), 1, "single class: {pattern}");
    analysis.classes[0].contains_scalar(scalar)
}

#[test]
fn identity_predecessors_sources_and_decision_are_fail_closed() {
    let value = contract();
    terminal_validate(&value).expect("terminal receipt must validate");

    for row in array(&value, "predecessors").expect("predecessors") {
        let path = text(row, "path").expect("predecessor path");
        assert_eq!(
            text(row, "sha256").expect("predecessor digest"),
            sha256(path)
        );
    }

    let expected_sources = [
        (
            SYNTAX_PATH,
            "2fbeae8fc1346d51cf5535930b750d0d69055d8923b3c6e8fcb3bf8ce25315b0",
            112_380,
        ),
        (
            SEMANTICS_PATH,
            "bd762181da7620330a580152688af7684da371a9a32c144ef09ac5b5d0c2221a",
            41_269,
        ),
        (
            BOUNDARIES_PATH,
            "bac41152af892d6fb3c84fcc4c1ee2a75d70219ec877604207dbcd4c8efafbbd",
            49_494,
        ),
    ];
    let sources = array(&value, "candidate_sources").expect("candidate sources");
    for (row, (path, digest, bytes)) in sources.iter().zip(expected_sources) {
        assert_eq!(text(row, "path").expect("source path"), path);
        assert_eq!(text(row, "sha256").expect("source digest"), digest);
        assert_eq!(sha256(path), digest);
        assert_eq!(number(row, "bytes").expect("source bytes"), bytes);
        assert_eq!(
            fs::metadata(path).expect("source metadata").len(),
            bytes,
            "source byte count drifted: {path}"
        );
    }
}

#[test]
fn official_unicode_authority_and_vector_registry_are_exact() {
    let value = contract();
    let authority = Value::Object(
        object(&value, "unicode_authority")
            .expect("Unicode authority")
            .clone(),
    );
    assert_eq!(text(&authority, "version").expect("version"), "16.0.0");
    assert_eq!(
        text(&authority, "archive_sha256").expect("archive digest"),
        "c86dd81f2b14a43b0cc064aa5f89aa7241386801e35c59c7984e579832634eb2"
    );
    let expected_files = BTreeSet::from([
        (
            "CaseFolding.txt",
            "6f1f9c588eb4a5c718d9e8f93b782685e5c7fec872cf05e8e6878053599e09bb",
        ),
        (
            "DerivedCoreProperties.txt",
            "39d35161f2954497f69e08bdb9e701493f476a3d30222de20028feda36c1dabd",
        ),
        (
            "PropList.txt",
            "53d614508e2a0b2305a8aa21cd60d993de9326cdf65993660dfcce4503548583",
        ),
        (
            "UnicodeData.txt",
            "ff58e5823bd095166564a006e47d111130813dcf8bf234ef79fa51a870edb48f",
        ),
    ]);
    let actual_files = array(&authority, "files")
        .expect("authority files")
        .iter()
        .map(|row| {
            (
                text(row, "path").expect("authority path"),
                text(row, "sha256").expect("authority digest"),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_files, expected_files);
    assert_eq!(
        array(&authority, "simple_fold_statuses").expect("simple statuses"),
        [Value::from("C"), Value::from("S")]
    );
    assert_eq!(
        array(&authority, "excluded_default_simple_fold_statuses").expect("excluded statuses"),
        [Value::from("F"), Value::from("T")]
    );
    assert!(!boolean(&authority, "normalization_performed").expect("normalization"));
    assert!(!boolean(&authority, "locale_sensitive_folding_performed").expect("locale folding"));

    let corpus = Value::Object(
        object(&value, "conformance_corpus")
            .expect("conformance corpus")
            .clone(),
    );
    let ids = array(&corpus, "rows")
        .expect("vector rows")
        .iter()
        .map(|row| text(row, "case_id").expect("case id"))
        .collect::<BTreeSet<_>>();
    assert_eq!(ids.len(), 20);
    assert!(ids.contains("RGX-R324-U001"));
    assert!(ids.contains("RGX-R324-F005"));
    assert!(ids.contains("RGX-R324-B002"));
}

#[test]
fn class_vectors_match_frozen_ucd_expectations_and_quarantined_incumbent() {
    let age_16 = [r"\p", "{Age:V16_0}"].concat();
    let hiragana_script_extension = [r"\p", "{scx:Hira}"].concat();
    let vectors = [
        (age_16.as_str(), '\u{1C89}', '\u{0378}'),
        (r"\p{Extended_Pictographic}", '😀', 'A'),
        (r"\p{Letter}", 'Σ', '1'),
        (r"\p{M}", '\u{0301}', 'A'),
        (r"\d", '\u{0665}', '\u{00B2}'),
        (r"\s", '\u{00A0}', '\u{200B}'),
        (r"\w", '\u{200C}', '😀'),
        (r"\p{Greek}", 'Σ', 'A'),
        (hiragana_script_extension.as_str(), 'ー', 'A'),
        (r"\p{gcb=Extend}", '\u{0301}', 'A'),
        (r"\p{wb=Katakana}", 'カ', 'A'),
        (r"\p{sb=ATerm}", '.', 'A'),
    ];
    for (pattern, included, excluded) in vectors {
        assert!(
            class_matches(pattern, included),
            "candidate omitted {included:?}: {pattern}"
        );
        assert!(
            !class_matches(pattern, excluded),
            "candidate admitted {excluded:?}: {pattern}"
        );

        let incumbent = Regex::new(&format!(r"\A(?:{pattern})\z"))
            .unwrap_or_else(|error| panic!("incumbent {pattern:?}: {error}"));
        assert!(incumbent.is_match(&included.to_string()));
        assert!(!incumbent.is_match(&excluded.to_string()));
    }
}

#[test]
fn dotted_age_value_spelling_is_an_explicit_minimized_keep_defer() {
    let dotted = [r"\p", "{Age:16.0}"].concat();
    let candidate = regex_semantics::analyze(
        &dotted,
        LexerLimits::default(),
        ParserLimits::default(),
        SemanticLimits::default(),
    )
    .expect_err("dotted Age value spelling is outside the staged syntax");
    assert_eq!(
        candidate.kind,
        SemanticErrorKind::Lex(regex_syntax::LexErrorKind::MalformedEscape)
    );
    assert!(candidate.to_string().starts_with("[RGX-LEX-E004]"));

    let incumbent =
        Regex::new(&format!(r"\A(?:{dotted})\z")).expect("incumbent dotted Age spelling");
    assert!(incumbent.is_match("\u{1C89}"));
    assert!(!incumbent.is_match("\u{0378}"));

    let value = contract();
    let corpus = Value::Object(
        object(&value, "conformance_corpus")
            .expect("conformance corpus")
            .clone(),
    );
    let minimized = array(&corpus, "minimized_failures").expect("minimized failures");
    assert_eq!(minimized.len(), 1);
    assert_eq!(
        text(&minimized[0], "resolution").expect("resolution"),
        "KEEP_DEFER_DOTTED_VALUE_SPELLING"
    );
    assert_eq!(
        text(&minimized[0], "canonical_candidate_replay").expect("canonical replay"),
        [r"\p", "{Age:V16_0}"].concat()
    );
}

#[test]
fn simple_fold_vectors_apply_c_and_s_but_not_f_or_t_rows() {
    let vectors: &[(&str, &[char])] = &[
        ("(?i:a)", &['a', 'A']),
        ("(?i:σ)", &['σ', 'Σ', 'ς']),
        ("(?i:k)", &['k', 'K', '\u{212A}']),
        ("(?i:å)", &['å', 'Å', '\u{212B}']),
        ("(?i:ω)", &['ω', 'Ω', '\u{2126}']),
        ("(?i:s)", &['s', 'S', '\u{017F}']),
        ("(?i:μ)", &['μ', 'Μ', '\u{00B5}']),
    ];
    for (pattern, equivalents) in vectors {
        let candidate = folded(pattern);
        assert_eq!(candidate.folds.len(), 1, "one fold atom: {pattern}");
        let incumbent = Regex::new(&format!(r"\A(?:{pattern})\z"))
            .unwrap_or_else(|error| panic!("incumbent {pattern:?}: {error}"));
        for scalar in *equivalents {
            assert!(
                candidate.folds[0].folded.matches_single_scalar(*scalar),
                "candidate omitted {scalar:?}: {pattern}"
            );
            assert!(incumbent.is_match(&scalar.to_string()));
        }
    }

    let sharp_s = folded("(?i:ß)");
    assert!(!sharp_s.folds[0].folded.matches_single_scalar('s'));
    assert!(!Regex::new(r"\A(?i:ß)\z").expect("sharp s").is_match("ss"));

    let dotted_i = folded("(?i:İ)");
    assert!(!dotted_i.folds[0].folded.matches_single_scalar('i'));
    let dotted_i_pattern = [r"\A", "(?i:İ)", r"\z"].concat();
    assert!(
        !Regex::new(&dotted_i_pattern)
            .expect("dotted I")
            .is_match("i")
    );
}

fn xorshift64(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn generated_patterns_are_deterministic_bounded_and_panic_free() {
    let atoms = [
        "a",
        "[a-z]",
        "[0-9]",
        "(?i:a)",
        r"\b",
        r"(?-u:\w)",
        "(?:x|y)",
        "^",
        "$",
        r"\A",
        r"\z",
    ];
    let mut state = GENERATED_SEED;
    for case_index in 0..1_024 {
        let atom_count = usize::try_from(xorshift64(&mut state) % 6 + 1).expect("bounded count");
        let mut pattern = String::new();
        for _ in 0..atom_count {
            let atom_variants = u64::try_from(atoms.len()).expect("atom count fits u64");
            let index =
                usize::try_from(xorshift64(&mut state) % atom_variants).expect("bounded index");
            pattern.push_str(atoms[index]);
        }

        let first = catch_unwind(AssertUnwindSafe(|| folded(&pattern)));
        assert!(
            first.is_ok(),
            "generated case {case_index} panicked: {pattern:?}"
        );
        let first = first.expect("panic checked");
        let second = folded(&pattern);
        assert_eq!(
            first, second,
            "generated case {case_index} was nondeterministic: {pattern:?}"
        );
        assert!(first.invariants_hold(
            &pattern,
            SemanticLimits::default(),
            FoldBoundaryLimits::default()
        ));
    }
}

fn word_formula(kind: BoundaryKind, left: bool, right: bool) -> bool {
    match kind {
        BoundaryKind::WordAscii | BoundaryKind::WordUnicode => left != right,
        BoundaryKind::NotWordAscii | BoundaryKind::NotWordUnicode => left == right,
        BoundaryKind::WordStartAscii | BoundaryKind::WordStartUnicode => !left && right,
        BoundaryKind::WordEndAscii | BoundaryKind::WordEndUnicode => left && !right,
        BoundaryKind::WordStartHalfAscii | BoundaryKind::WordStartHalfUnicode => !left,
        BoundaryKind::WordEndHalfAscii | BoundaryKind::WordEndHalfUnicode => !right,
        _ => panic!("word formula received non-word boundary"),
    }
}

#[test]
fn generated_word_pair_matrix_matches_independent_frozen_model() {
    let scalars = [
        ('a', true, true),
        ('_', true, true),
        ('5', true, true),
        ('β', false, true),
        ('\u{0301}', false, true),
        ('\u{200C}', false, true),
        ('\u{203F}', false, true),
        (' ', false, false),
        ('-', false, false),
        ('😀', false, false),
        ('\u{00A0}', false, false),
    ];
    let variants = [
        (BoundaryKind::WordAscii, false),
        (BoundaryKind::NotWordAscii, false),
        (BoundaryKind::WordStartAscii, false),
        (BoundaryKind::WordEndAscii, false),
        (BoundaryKind::WordStartHalfAscii, false),
        (BoundaryKind::WordEndHalfAscii, false),
        (BoundaryKind::WordUnicode, true),
        (BoundaryKind::NotWordUnicode, true),
        (BoundaryKind::WordStartUnicode, true),
        (BoundaryKind::WordEndUnicode, true),
        (BoundaryKind::WordStartHalfUnicode, true),
        (BoundaryKind::WordEndHalfUnicode, true),
    ];

    let mut cases = 0;
    for (left_char, left_ascii, left_unicode) in scalars {
        for (right_char, right_ascii, right_unicode) in scalars {
            cases += 1;
            let haystack = format!("{left_char}{right_char}");
            let offset = left_char.len_utf8();
            for (kind, unicode) in variants {
                let (left, right) = if unicode {
                    (left_unicode, right_unicode)
                } else {
                    (left_ascii, right_ascii)
                };
                assert_eq!(
                    kind.is_match(&haystack, offset).expect("valid offset"),
                    word_formula(kind, left, right),
                    "{kind:?}: {left_char:?}|{right_char:?}"
                );
            }
        }
    }
    assert_eq!(cases, 121);
}

#[test]
fn input_line_and_crlf_boundaries_cover_empty_and_edge_offsets() {
    let cases = [
        (BoundaryKind::InputStart, "", 0, true),
        (BoundaryKind::InputEnd, "", 0, true),
        (BoundaryKind::InputStart, "a", 1, false),
        (BoundaryKind::InputEnd, "a", 1, true),
        (BoundaryKind::LineStartLf, "a\nb", 2, true),
        (BoundaryKind::LineEndLf, "a\nb", 1, true),
        (BoundaryKind::LineStartCrlf, "a\r\nb", 2, false),
        (BoundaryKind::LineEndCrlf, "a\r\nb", 2, false),
        (BoundaryKind::LineStartCrlf, "a\r\nb", 3, true),
        (BoundaryKind::LineEndCrlf, "a\r\nb", 1, true),
        (BoundaryKind::LineStartCrlf, "a\rb", 2, true),
        (BoundaryKind::LineEndCrlf, "a\rb", 1, true),
    ];
    for (kind, haystack, offset, expected) in cases {
        assert_eq!(
            kind.is_match(haystack, offset).expect("valid offset"),
            expected,
            "{kind:?}: {haystack:?} at {offset}"
        );
    }

    let invalid = BoundaryKind::WordUnicode
        .is_match("é", 1)
        .expect_err("middle of UTF-8 scalar must fail");
    assert_eq!(invalid.kind, BoundaryEvalErrorKind::InvalidUtf8Offset);
}

#[test]
fn byte_hostile_limits_and_redaction_fail_closed() {
    let valid = semantic(r"(?-u:\xC2\xA0)");
    assert_eq!(valid.resources.byte_scopes_validated, 1);

    let invalid = regex_semantics::analyze(
        r"(?-u:\xFF)",
        LexerLimits::default(),
        ParserLimits::default(),
        SemanticLimits::default(),
    )
    .expect_err("isolated invalid byte must fail");
    assert_eq!(invalid.kind, SemanticErrorKind::InvalidUtf8Boundary);

    let property = regex_semantics::analyze(
        r"(?-u:\pL)",
        LexerLimits::default(),
        ParserLimits::default(),
        SemanticLimits::default(),
    )
    .expect_err("Unicode property in byte mode must fail");
    assert_eq!(property.kind, SemanticErrorKind::UnicodePropertyInByteMode);

    let semantic_budget = regex_semantics::analyze(
        "[a]",
        LexerLimits::default(),
        ParserLimits::default(),
        SemanticLimits {
            max_semantic_atoms: 0,
            ..SemanticLimits::default()
        },
    )
    .expect_err("zero semantic budget must fail");
    assert_eq!(semantic_budget.kind, SemanticErrorKind::SemanticAtomLimit);

    let boundary_budget = regex_boundaries::analyze(
        r"\b",
        LexerLimits::default(),
        ParserLimits::default(),
        SemanticLimits::default(),
        FoldBoundaryLimits {
            max_boundary_assertions: 0,
            ..FoldBoundaryLimits::default()
        },
    )
    .expect_err("zero boundary budget must fail");
    assert_eq!(boundary_budget.kind, FoldBoundaryErrorKind::BoundaryLimit);

    let canary = "PRIVATE_TERMINAL_PROPERTY_CANARY";
    let private_pattern = format!(r"\p{{{canary}}}");
    let private = regex_boundaries::analyze(
        &private_pattern,
        LexerLimits::default(),
        ParserLimits::default(),
        SemanticLimits::default(),
        FoldBoundaryLimits::default(),
    )
    .expect_err("private unknown property must fail");
    assert_eq!(
        private.kind,
        FoldBoundaryErrorKind::CharacterSemantics(SemanticErrorKind::UnknownUnicodeProperty)
    );
    let rendered = private.to_string();
    assert!(rendered.starts_with("[RGX-SEM-E001]"));
    assert!(!rendered.contains(canary));
    assert!(!rendered.contains(&private_pattern));
}

#[test]
fn size_targets_oracle_docs_and_proof_boundaries_are_explicit() {
    let value = contract();
    let size = Value::Object(object(&value, "size_audit").expect("size audit").clone());
    assert_eq!(
        number(&size, "candidate_source_bytes").expect("candidate bytes"),
        203_143
    );
    assert_eq!(
        number(&size, "retained_module_plus_table_bytes").expect("retained bytes"),
        788_324
    );
    assert!(!boolean(&size, "candidate_is_table_replacement").expect("table replacement"));
    assert!(!boolean(&size, "source_reduction_claim_authorized").expect("source reduction"));
    assert!(boolean(&size, "isolated_release_artifact_bytes_measured").expect("artifact measured"));

    let probe = Value::Object(
        object(&size, "compile_probe")
            .expect("compile probe")
            .clone(),
    );
    assert!(!boolean(&probe, "admissible_delta").expect("admissible delta"));
    assert_eq!(
        number(&probe, "base_build_id").expect("base build"),
        29_947_326_818_680_932
    );
    assert_eq!(
        number(&probe, "metrics_build_id").expect("metrics build"),
        29_947_326_818_680_933
    );
    assert_eq!(
        number(&probe, "base_rlib_bytes").expect("base rlib"),
        328_640_544
    );
    assert_eq!(
        number(&probe, "metrics_rlib_bytes").expect("metrics rlib"),
        331_072_512
    );
    assert_eq!(
        number(&probe, "rlib_delta_bytes").expect("rlib delta"),
        2_431_968
    );
    assert_eq!(
        number(&probe, "cold_runs_per_profile_completed").expect("cold runs"),
        1
    );
    assert_eq!(
        number(&probe, "required_cold_runs_per_profile").expect("required cold runs"),
        5
    );
    assert_eq!(
        text(&probe, "disposition").expect("probe disposition"),
        "KEEP_INCUMBENT_DEFER"
    );
    assert!(!boolean(&probe, "local_fallback_used").expect("local fallback"));

    let oracle = Value::Object(object(&value, "oracle").expect("oracle").clone());
    assert_eq!(
        text(&oracle, "review_by_utc").expect("oracle review"),
        "2027-07-25"
    );
    assert_eq!(
        text(&oracle, "expiry_disposition").expect("expiry disposition"),
        "KEEP_INCUMBENT_DEFER"
    );
    assert!(
        array(&oracle, "invalidation_events")
            .expect("invalidation events")
            .len()
            >= 6
    );

    let targets = array(&value, "target_matrix").expect("target matrix");
    assert_eq!(
        text(&targets[0], "execution_state").expect("native target state"),
        "PASSED_FOCUSED_REMOTE_SEMANTIC_PROOF"
    );
    assert_eq!(
        text(&targets[0], "decision").expect("native target decision"),
        "SCOPED_SEMANTIC_PROOF_ONLY"
    );

    let proof = Value::Object(object(&value, "proof").expect("proof").clone());
    let focused = Value::Object(
        object(&proof, "focused_contract_test")
            .expect("focused test")
            .clone(),
    );
    assert_eq!(text(&focused, "state").expect("test state"), "PASSED");
    assert_eq!(
        number(&focused, "build_id").expect("test build"),
        29_947_326_818_680_936
    );
    assert_eq!(number(&focused, "tests_passed").expect("tests passed"), 72);
    assert_eq!(number(&focused, "tests_failed").expect("tests failed"), 0);
    assert!(!boolean(&focused, "local_fallback_used").expect("test fallback"));

    let clippy = Value::Object(
        object(&proof, "focused_clippy")
            .expect("focused Clippy")
            .clone(),
    );
    assert_eq!(text(&clippy, "state").expect("Clippy state"), "PASSED");
    assert_eq!(
        number(&clippy, "build_id").expect("Clippy build"),
        29_947_326_818_680_938
    );
    assert!(!boolean(&clippy, "local_fallback_used").expect("Clippy fallback"));
    assert_eq!(
        array(&proof, "corrected_attempts")
            .expect("corrected attempts")
            .len(),
        3
    );

    let docs = read(DOC_PATH);
    for marker in [
        "<!-- BEGIN REGEX SEMANTIC TERMINAL RECEIPT -->",
        "`KEEP_INCUMBENT_DEFER`",
        "`ASUP-REGEX-SEMANTICS-TERMINAL-V1`",
        "R3.3 compiler experimentation is authorized",
        "1,024 deterministic generated",
        "121 generated word-status",
        "cold same-worker runs",
        "AArch64 and wasm32 remain",
        "No local Cargo fallback is approved.",
        "does not authorize production wiring",
        "<!-- END REGEX SEMANTIC TERMINAL RECEIPT -->",
    ] {
        assert!(docs.contains(marker), "missing docs marker: {marker}");
    }
}

#[test]
fn decision_predecessor_conformance_and_target_mutations_fail_closed() {
    let base = contract();
    let mut mutations = Vec::new();

    let mut cutover = base.clone();
    cutover["decision"]["production_cutover_eligible"] = Value::Bool(true);
    mutations.push(cutover);

    let mut removal = base.clone();
    removal["decision"]["dependency_removal_authorized"] = Value::Bool(true);
    mutations.push(removal);

    let mut predecessor = base.clone();
    predecessor["predecessors"][0]["sha256"] = Value::from("drift");
    mutations.push(predecessor);

    let mut regression = base.clone();
    regression["conformance_corpus"]["rows"][0]["result"] = Value::from("REGRESSION");
    mutations.push(regression);

    let mut arm_green = base;
    arm_green["target_matrix"][1]["execution_state"] = Value::from("PASSED");
    mutations.push(arm_green);

    for mutation in mutations {
        assert!(terminal_validate(&mutation).is_err());
    }
}
