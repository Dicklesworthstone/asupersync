#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

use asupersync::messaging::{Subject, SubjectPattern, SubjectPatternError, SubjectToken};

static FIXED_CANARIES: OnceLock<()> = OnceLock::new();

fn concrete_subject_for(pattern: &SubjectPattern) -> String {
    pattern
        .segments()
        .iter()
        .enumerate()
        .flat_map(|(idx, segment)| match segment {
            SubjectToken::Literal(value) => vec![value.clone()],
            SubjectToken::One => vec![format!("single{idx}")],
            SubjectToken::Tail => vec![format!("tail{idx}"), format!("leaf{idx}")],
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn observe_pattern_methods(pattern: &SubjectPattern) {
    let segments = pattern.segments();
    let expected_has_wildcards = segments
        .iter()
        .any(|segment| !matches!(segment, SubjectToken::Literal(_)));
    let has_wildcards = pattern.has_wildcards();
    assert_eq!(
        has_wildcards, expected_has_wildcards,
        "has_wildcards should mirror parsed token shape"
    );

    let expected_full_wildcard = matches!(segments.last(), Some(SubjectToken::Tail));
    let is_full_wildcard = pattern.is_full_wildcard();
    assert_eq!(
        is_full_wildcard, expected_full_wildcard,
        "is_full_wildcard should track a terminal tail wildcard"
    );
    if is_full_wildcard {
        assert!(
            has_wildcards,
            "a terminal tail wildcard should also count as a wildcard"
        );
    }

    assert_eq!(
        pattern.canonical_key(),
        pattern.as_str(),
        "canonical_key should mirror as_str"
    );
}

fn observe_parse_error(input: &str, error: &impl std::fmt::Display) {
    assert!(
        !error.to_string().is_empty(),
        "rejected subject pattern should expose a diagnostic for {input:?}"
    );
}

fn assert_subject_pattern_error(
    input: &str,
    expected_error: SubjectPatternError,
    expected_display: &str,
) {
    let error =
        SubjectPattern::parse(input).expect_err("fixed subject pattern canary should be rejected");
    assert_eq!(
        error, expected_error,
        "subject pattern parser returned the wrong error variant for {input:?}"
    );
    assert_eq!(
        error.to_string(),
        expected_display,
        "subject pattern parser display text drifted for {input:?}"
    );
}

fn assert_fixed_subject_pattern_error_canaries() {
    assert_subject_pattern_error(
        "",
        SubjectPatternError::EmptyPattern,
        "subject pattern must contain at least one segment",
    );
    assert_subject_pattern_error(
        "tenant..orders",
        SubjectPatternError::EmptySegment,
        "subject pattern must not contain empty segments",
    );
    assert_subject_pattern_error(
        "tenant.order status",
        SubjectPatternError::WhitespaceInSegment("order status".to_string()),
        "subject segment `order status` must not contain whitespace",
    );
    assert_subject_pattern_error(
        "tenant.>.orders",
        SubjectPatternError::TailWildcardMustBeTerminal,
        "tail wildcard `>` must be terminal",
    );
    assert_subject_pattern_error(
        "tenant.>.>",
        SubjectPatternError::MultipleTailWildcards,
        "subject pattern may not contain more than one tail wildcard",
    );
    assert_subject_pattern_error(
        "tenant.or*ders",
        SubjectPatternError::EmbeddedWildcard("or*ders".to_string()),
        "literal segment `or*ders` embeds wildcard characters",
    );
}

// Fuzz target for messaging subject pattern parser.
//
// Tests the SubjectPattern::parse function with arbitrary byte inputs,
// ensuring it handles malformed input gracefully without panicking.
fuzz_target!(|data: &[u8]| {
    FIXED_CANARIES.get_or_init(assert_fixed_subject_pattern_error_canaries);

    // Convert raw bytes to string (lossy conversion is fine for fuzzing)
    let input = String::from_utf8_lossy(data);

    // Property 1: Parser should never panic on any input
    let parse_result = std::panic::catch_unwind(|| SubjectPattern::parse(&input));

    // Should handle panic-free
    assert!(
        parse_result.is_ok(),
        "SubjectPattern::parse panicked on input: {:?}",
        input
    );

    // Property 2: If parsing succeeds, the result should be well-formed
    if let Ok(Ok(ref pattern)) = parse_result {
        // Should have a valid string representation
        let canonical = pattern.as_str();
        assert!(
            !canonical.is_empty(),
            "Valid pattern should have non-empty canonical form"
        );

        // Should have segments
        let segments = pattern.segments();
        assert!(
            !segments.is_empty(),
            "Valid pattern should have at least one segment"
        );

        // Property 3: Round-trip consistency
        // If we can parse it, we should be able to re-parse the canonical form
        let reparsed = SubjectPattern::parse(canonical)
            .unwrap_or_else(|err| panic!("canonical form should re-parse: {canonical}: {err}"));
        assert_eq!(
            &reparsed, pattern,
            "canonical parse should be stable for {canonical}"
        );
        assert_eq!(
            pattern.canonical_key(),
            canonical,
            "canonical key must mirror as_str"
        );

        // Property 4: Pattern helpers should agree with parsed tokens.
        observe_pattern_methods(pattern);

        // Property 5: A synthesized concrete subject should match the
        // parsed pattern, and overlap must be symmetric against the
        // corresponding literal pattern.
        let concrete = concrete_subject_for(pattern);
        let subject = Subject::parse(&concrete)
            .unwrap_or_else(|err| panic!("synthesized subject should parse: {concrete}: {err}"));
        assert!(
            pattern.matches(&subject),
            "pattern {canonical} should match synthesized subject {concrete}"
        );

        let concrete_pattern = SubjectPattern::from(&subject);
        assert!(
            pattern.overlaps(&concrete_pattern),
            "pattern {canonical} should overlap concrete subject pattern {concrete}"
        );
        assert!(
            concrete_pattern.overlaps(pattern),
            "overlap must be symmetric for {canonical} and {concrete}"
        );

        assert!(
            pattern.overlaps(&reparsed) && reparsed.overlaps(pattern),
            "a pattern must overlap its canonical reparse"
        );
    }

    // Property 6: Error cases should return proper errors, not panics
    if let Ok(Err(ref error)) = parse_result {
        // This is expected for malformed input - the parser correctly rejected it
        observe_parse_error(&input, error);
    }
});
