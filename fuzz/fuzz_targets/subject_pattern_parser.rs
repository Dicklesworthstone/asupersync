#![no_main]

use libfuzzer_sys::fuzz_target;

use asupersync::messaging::{Subject, SubjectPattern, SubjectToken};

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

// Fuzz target for messaging subject pattern parser.
//
// Tests the SubjectPattern::parse function with arbitrary byte inputs,
// ensuring it handles malformed input gracefully without panicking.
fuzz_target!(|data: &[u8]| {
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

        // Property 4: Pattern methods should not panic
        let _ = pattern.has_wildcards();
        let _ = pattern.is_full_wildcard();
        let _ = pattern.canonical_key();

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
    if let Ok(Err(error)) = parse_result {
        // This is expected for malformed input - the parser correctly rejected it
        let _ = error;
    }
});
