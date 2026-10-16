    use super::*;
    use proptest::prelude::*;

    fn default_analyze(pattern: &str) -> Result<SemanticAnalysis, SemanticError> {
        analyze(
            pattern,
            LexerLimits::default(),
            ParserLimits::default(),
            SemanticLimits::default(),
        )
    }

    fn only_class(pattern: &str) -> CanonicalClass {
        let analysis = default_analyze(pattern).expect("fixture must have valid semantics");
        assert_eq!(analysis.classes.len(), 1);
        analysis.classes[0].clone()
    }

    #[test]
    fn unicode_property_and_set_algebra_use_pinned_tables() {
        let class = only_class(r"[\pL&&\p{Greek}]");
        assert_eq!(class.alphabet(), ClassAlphabet::UnicodeScalar);
        assert!(class.contains_scalar('κ'));
        assert!(class.contains_scalar('Σ'));
        assert!(!class.contains_scalar('A'));
        assert!(class.ranges.is_canonical());
    }

    #[test]
    fn extended_mode_is_preserved_for_retained_semantic_fragments() {
        let pattern = "(?x) \\p { Greek } # semantic fragment comment\n (?x-u: \\x {41})";
        let analysis = default_analyze(pattern).expect("extended fragments must compile");
        assert_eq!(analysis.classes.len(), 1);
        assert!(analysis.classes[0].contains_scalar('κ'));
        assert!(!analysis.classes[0].contains_scalar('A'));
        assert_eq!(analysis.resources.byte_scopes_validated, 1);
        assert!(analysis.invariants_hold(pattern, SemanticLimits::default()));
    }

    #[test]
    fn union_negation_ranges_and_ascii_posix_classes_are_canonical() {
        let consonants = only_class("[a-z&&[^aeiou]]");
        assert!(consonants.contains_scalar('b'));
        assert!(consonants.contains_scalar('z'));
        assert!(!consonants.contains_scalar('a'));
        assert!(!consonants.contains_scalar('é'));

        let digits = only_class("[[:digit:]]");
        assert!(digits.contains_scalar('0'));
        assert!(digits.contains_scalar('9'));
        assert!(!digits.contains_scalar('١'));
    }

    #[test]
    fn unicode_and_ascii_perl_classes_preserve_flag_scope() {
        let analysis = default_analyze(r"\d(?-u:\d)\d").expect("scoped classes must compile");
        assert_eq!(analysis.classes.len(), 3);
        assert_eq!(analysis.classes[0].alphabet(), ClassAlphabet::UnicodeScalar);
        assert_eq!(analysis.classes[1].alphabet(), ClassAlphabet::Utf8SafeByte);
        assert_eq!(analysis.classes[2].alphabet(), ClassAlphabet::UnicodeScalar);
        assert!(analysis.classes[0].contains_scalar('١'));
        assert!(!analysis.classes[1].contains_scalar('١'));
        assert!(analysis.classes[1].contains_scalar('7'));
    }

    #[test]
    fn combining_marks_edge_scalars_and_noncharacters_are_explicit() {
        let marks = only_class(r"\p{M}");
        assert!(marks.contains_scalar('\u{0301}'));
        assert!(!marks.contains_scalar('A'));

        let edges = only_class(r"[\u{0}\u{FDD0}\u{10FFFF}]");
        assert!(edges.contains_scalar('\0'));
        assert!(edges.contains_scalar('\u{FDD0}'));
        assert!(edges.contains_scalar('\u{10FFFF}'));
        assert!(!edges.contains_scalar('\u{FFFD}'));
    }

    #[test]
    fn unknown_properties_fail_closed_without_rendering_source() {
        let pattern = r"\p{DefinitelyNotAProperty_private-source-canary}";
        let error = default_analyze(pattern).expect_err("unknown property must fail");
        assert_eq!(error.kind, SemanticErrorKind::UnknownUnicodeProperty);
        assert_eq!(error.kind.code(), "RGX-SEM-E001");
        assert!(!error.to_string().contains("private-source-canary"));
    }

    #[test]
    fn unicode_properties_are_forbidden_when_unicode_mode_is_disabled() {
        let error = default_analyze(r"(?-u:\pL)").expect_err("byte property must fail");
        assert_eq!(error.kind, SemanticErrorKind::UnicodePropertyInByteMode);
        assert_eq!(
            error.kind.diagnostic_category(),
            "RGX-DIAG-UNICODE-PROPERTY-IN-BYTE-MODE"
        );
    }

    #[test]
    fn utf8_safe_byte_classes_are_kept_and_invalid_bytes_are_rejected() {
        let class = only_class(r"(?-u:[a-z])");
        assert_eq!(class.alphabet(), ClassAlphabet::Utf8SafeByte);
        assert!(class.contains_scalar('a'));
        assert!(!class.contains_scalar('é'));

        let error = default_analyze(r"(?-u:\xFF)").expect_err("invalid byte must fail");
        assert_eq!(error.kind, SemanticErrorKind::InvalidUtf8Boundary);
        assert_eq!(error.kind.code(), "RGX-SEM-E003");
    }

    #[test]
    fn byte_mode_accepts_only_sequences_that_preserve_string_utf8() {
        let escaped =
            default_analyze(r"(?-u:\xC2\xA0)").expect("paired byte escapes form valid UTF-8");
        assert_eq!(escaped.resources.byte_scopes_validated, 1);
        assert!(escaped.invariants_hold(r"(?-u:\xC2\xA0)", SemanticLimits::default()));

        let literal = default_analyze("(?-u:é)").expect("raw scalar remains valid UTF-8");
        assert_eq!(literal.resources.byte_scopes_validated, 1);

        for pattern in [r"(?-u:\xC2|\xA0)", r"(?-u:\xC2\xA0*)"] {
            let error = default_analyze(pattern).expect_err("every match must preserve UTF-8");
            assert_eq!(error.kind, SemanticErrorKind::InvalidUtf8Boundary);
        }
    }

    #[test]
    fn semantic_atom_and_range_budgets_fail_before_unbounded_growth() {
        let atom_error = analyze(
            r"\d\s",
            LexerLimits::default(),
            ParserLimits::default(),
            SemanticLimits {
                max_semantic_atoms: 1,
                ..SemanticLimits::default()
            },
        )
        .expect_err("second semantic atom must exceed the limit");
        assert_eq!(atom_error.kind, SemanticErrorKind::SemanticAtomLimit);

        let any_pattern = concat!(r"\p{", "any}");
        let any = default_analyze(any_pattern).expect("Unicode scalar universe must compile");
        assert_eq!(any.resources.total_ranges, 1);
        assert_eq!(any.resources.represented_values, 0x11_0000 - 0x800);

        let range_error = analyze(
            r"\p{Greek}",
            LexerLimits::default(),
            ParserLimits::default(),
            SemanticLimits {
                max_ranges_per_class: 1,
                ..SemanticLimits::default()
            },
        )
        .expect_err("Greek requires more than one canonical range");
        assert_eq!(range_error.kind, SemanticErrorKind::ClassRangeLimit);
    }

    #[test]
    fn accounting_and_canonical_invariants_reconcile() {
        let pattern = r"[a-z]\p{Greek}(?-u:\w).";
        let analysis = default_analyze(pattern).expect("fixture must compile");
        assert!(analysis.invariants_hold(pattern, SemanticLimits::default()));
        assert_eq!(analysis.resources.semantic_atoms, 4);
        assert_eq!(analysis.resources.unicode_property_references, 1);
        assert_eq!(analysis.resources.byte_scopes_validated, 1);
        assert_eq!(analysis.resources.unicode_classes, 3);
        assert_eq!(analysis.resources.byte_classes, 1);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn ascii_ranges_agree_with_the_closed_interval_model(
            left in b'a'..=b'z',
            right in b'a'..=b'z',
            probe in b'a'..=b'z',
        ) {
            let (start, end) = if left <= right {
                (left, right)
            } else {
                (right, left)
            };
            let pattern = format!("[{}-{}]", char::from(start), char::from(end));
            let class = only_class(&pattern);
            prop_assert_eq!(
                class.contains_scalar(char::from(probe)),
                start <= probe && probe <= end
            );
        }

        #[test]
        fn arbitrary_utf8_semantic_inputs_are_panic_free_and_deterministic(
            scalars in proptest::collection::vec(any::<char>(), 0..64),
        ) {
            let pattern: String = scalars.into_iter().collect();
            let left = default_analyze(&pattern);
            let right = default_analyze(&pattern);
            prop_assert_eq!(left, right);
        }
    }
