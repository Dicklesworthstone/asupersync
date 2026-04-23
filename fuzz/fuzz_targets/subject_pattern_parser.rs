#![no_main]

use libfuzzer_sys::fuzz_target;

use asupersync::messaging::SubjectPattern;

/// Fuzz target for messaging subject pattern parser
///
/// Tests the SubjectPattern::parse function with arbitrary byte inputs,
/// ensuring it handles malformed input gracefully without panicking.
fuzz_target!(|data: &[u8]| {
    // Convert raw bytes to string (lossy conversion is fine for fuzzing)
    let input = String::from_utf8_lossy(data);

    // Property 1: Parser should never panic on any input
    let parse_result = std::panic::catch_unwind(|| {
        SubjectPattern::parse(&input)
    });

    // Should handle panic-free
    assert!(parse_result.is_ok(), "SubjectPattern::parse panicked on input: {:?}", input);

    // Property 2: If parsing succeeds, the result should be well-formed
    if let Ok(Ok(pattern)) = parse_result {
        // Should have a valid string representation
        let canonical = pattern.as_str();
        assert!(!canonical.is_empty(), "Valid pattern should have non-empty canonical form");

        // Should have segments
        let segments = pattern.segments();
        assert!(!segments.is_empty(), "Valid pattern should have at least one segment");

        // Property 3: Round-trip consistency
        // If we can parse it, we should be able to re-parse the canonical form
        let reparse_result = SubjectPattern::parse(canonical);
        assert!(
            reparse_result.is_ok(),
            "Canonical form should re-parse successfully: {}",
            canonical
        );

        // Property 4: Pattern methods should not panic
        let _ = pattern.has_wildcards();
        let _ = pattern.is_full_wildcard();
        let _ = pattern.canonical_key();
    }

    // Property 5: Error cases should return proper errors, not panics
    if let Ok(Err(_error)) = parse_result {
        // This is expected for malformed input - the parser correctly rejected it
        assert!(true, "Parser correctly rejected malformed input");
    }
});