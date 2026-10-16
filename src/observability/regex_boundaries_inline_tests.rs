    use super::*;
    use proptest::prelude::*;

    fn default_analyze(pattern: &str) -> Result<FoldBoundaryAnalysis, FoldBoundaryError> {
        analyze(
            pattern,
            LexerLimits::default(),
            ParserLimits::default(),
            SemanticLimits::default(),
            FoldBoundaryLimits::default(),
        )
    }

    #[test]
    fn ascii_simple_fold_and_flag_scope_are_exact() {
        let analysis = default_analyze("a(?i:b)(?-i:c)(?i-u:d)").expect("valid folding fixture");
        assert_eq!(analysis.folds.len(), 2);
        assert!(analysis.folds[0].folded.matches_single_scalar('b'));
        assert!(analysis.folds[0].folded.matches_single_scalar('B'));
        assert_eq!(analysis.folds[0].alphabet(), FoldAlphabet::UnicodeScalar);
        assert!(analysis.folds[1].folded.matches_single_scalar('d'));
        assert!(analysis.folds[1].folded.matches_single_scalar('D'));
        assert_eq!(analysis.folds[1].alphabet(), FoldAlphabet::Utf8SafeAscii);
        assert_eq!(analysis.resources.expanded_fold_atoms, 2);
    }

    #[test]
    fn unicode_simple_fold_uses_sigma_and_kelvin_equivalence() {
        let sigma = default_analyze("(?i:σ)").expect("sigma fold must compile");
        let sigma = &sigma.folds[0].folded;
        assert!(sigma.matches_single_scalar('σ'));
        assert!(sigma.matches_single_scalar('Σ'));
        assert!(sigma.matches_single_scalar('ς'));

        let kelvin = default_analyze("(?i:k)").expect("Kelvin fold must compile");
        let kelvin = &kelvin.folds[0].folded;
        assert!(kelvin.matches_single_scalar('k'));
        assert!(kelvin.matches_single_scalar('K'));
        assert!(kelvin.matches_single_scalar('\u{212A}'));
    }

    #[test]
    fn multi_scalar_locale_and_normalization_expansions_are_explicitly_absent() {
        assert_eq!(FOLDING_KIND, "UNICODE_SIMPLE_ONE_SCALAR");
        assert!(!MULTI_SCALAR_FOLDS_SUPPORTED);
        assert!(!LOCALE_SENSITIVE_FOLDS_SUPPORTED);
        assert!(!NORMALIZATION_PERFORMED);

        let sharp_s = default_analyze("(?i:ß)").expect("simple sharp-s semantics must compile");
        assert_eq!(sharp_s.folds.len(), 1);
        assert!(sharp_s.folds[0].folded.matches_single_scalar('ß'));
        assert!(!sharp_s.folds[0].folded.matches_single_scalar('s'));

        let decomposed = default_analyze("(?i:e\u{301})").expect("combining sequence must compile");
        assert_eq!(decomposed.folds.len(), 2);
        assert!(decomposed.folds[1].folded.matches_single_scalar('\u{301}'));
        assert!(!decomposed.folds[1].expanded());
    }

    #[test]
    fn byte_mode_folds_ascii_only_and_preserves_validated_non_ascii_bytes() {
        let ascii = default_analyze("(?i-u:a)").expect("ASCII byte fold must compile");
        assert_eq!(ascii.folds[0].alphabet(), FoldAlphabet::Utf8SafeAscii);
        assert!(ascii.folds[0].folded.matches_single_scalar('A'));
        assert!(!ascii.folds[0].folded.matches_single_scalar('\u{212A}'));

        let non_ascii = default_analyze("(?i-u:é)").expect("UTF-8 literal scope must compile");
        assert_eq!(
            non_ascii.folds[0].alphabet(),
            FoldAlphabet::Utf8ValidatedByteSequence
        );
        assert!(!non_ascii.folds[0].expanded());
        assert!(non_ascii.folds[0].folded.matches_single_scalar('é'));
        assert!(!non_ascii.folds[0].folded.matches_single_scalar('É'));
    }

    #[test]
    fn folded_classes_are_canonical_and_bounded() {
        let analysis = default_analyze(r"(?i:[a-z&&[^q]])").expect("folded class must compile");
        assert_eq!(analysis.folds.len(), 1);
        let fold = &analysis.folds[0];
        assert!(fold.expanded());
        assert!(fold.folded.matches_single_scalar('A'));
        assert!(!fold.folded.matches_single_scalar('Q'));
        assert!(fold.folded.invariants_hold());
        assert!(analysis.invariants_hold(
            r"(?i:[a-z&&[^q]])",
            SemanticLimits::default(),
            FoldBoundaryLimits::default()
        ));
    }

    #[test]
    fn input_and_lf_line_boundaries_cover_empty_and_newline_inputs() {
        for kind in [BoundaryKind::InputStart, BoundaryKind::InputEnd] {
            assert!(kind.is_match("", 0).expect("valid boundary"));
        }
        assert!(
            BoundaryKind::LineStartLf
                .is_match("a\nb", 2)
                .expect("valid boundary")
        );
        assert!(
            BoundaryKind::LineEndLf
                .is_match("a\nb", 1)
                .expect("valid boundary")
        );
        assert!(
            !BoundaryKind::LineStartLf
                .is_match("a\nb", 1)
                .expect("valid boundary")
        );
        assert!(
            !BoundaryKind::LineEndLf
                .is_match("a\nb", 2)
                .expect("valid boundary")
        );
    }

    #[test]
    fn crlf_boundaries_never_split_a_pair_but_accept_lone_terminators() {
        let crlf = "a\r\nb";
        assert!(
            BoundaryKind::LineEndCrlf
                .is_match(crlf, 1)
                .expect("before CR")
        );
        assert!(
            !BoundaryKind::LineEndCrlf
                .is_match(crlf, 2)
                .expect("between CRLF")
        );
        assert!(
            !BoundaryKind::LineStartCrlf
                .is_match(crlf, 2)
                .expect("between CRLF")
        );
        assert!(
            BoundaryKind::LineStartCrlf
                .is_match(crlf, 3)
                .expect("after LF")
        );

        assert!(
            BoundaryKind::LineStartCrlf
                .is_match("a\rb", 2)
                .expect("after lone CR")
        );
        assert!(
            BoundaryKind::LineEndCrlf
                .is_match("a\nb", 1)
                .expect("before lone LF")
        );
    }

    #[test]
    fn unicode_and_ascii_word_transitions_differ_without_locale() {
        let greek = " κόσμος ";
        assert!(
            BoundaryKind::WordUnicode
                .is_match(greek, 1)
                .expect("Unicode table available")
        );
        assert!(
            !BoundaryKind::WordAscii
                .is_match(greek, 1)
                .expect("ASCII boundary")
        );

        let combining = " \u{301} ";
        assert!(
            BoundaryKind::WordUnicode
                .is_match(combining, 1)
                .expect("mark is Unicode word")
        );
        assert!(
            !BoundaryKind::WordAscii
                .is_match(combining, 1)
                .expect("mark is not ASCII word")
        );

        assert!(
            BoundaryKind::WordAscii
                .is_match("$a", 1)
                .expect("ASCII start")
        );
        assert!(
            BoundaryKind::NotWordAscii
                .is_match("aa", 1)
                .expect("inside word")
        );
    }

    #[test]
    fn directional_and_half_word_variants_have_distinct_truth_tables() {
        assert!(
            BoundaryKind::WordStartUnicode
                .is_match("-β", 1)
                .expect("word start")
        );
        assert!(
            !BoundaryKind::WordEndUnicode
                .is_match("-β", 1)
                .expect("not word end")
        );
        assert!(
            BoundaryKind::WordEndUnicode
                .is_match("β-", 2)
                .expect("word end")
        );
        assert!(
            BoundaryKind::WordStartHalfUnicode
                .is_match("--", 1)
                .expect("left is non-word")
        );
        assert!(
            BoundaryKind::WordEndHalfUnicode
                .is_match("--", 1)
                .expect("right is non-word")
        );
    }

    #[test]
    fn parser_flags_select_exact_boundary_variants_and_restore_scope() {
        let pattern =
            r"^\A(?m:^$(?R:$))$(?-u:\b\B\b{start}\b{end}\b{start-half}\b{end-half})\b\<\>\z";
        let analysis = default_analyze(pattern).expect("boundary fixture must compile");
        let kinds = analysis
            .boundaries
            .iter()
            .map(|boundary| boundary.kind)
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            vec![
                BoundaryKind::InputStart,
                BoundaryKind::InputStart,
                BoundaryKind::LineStartLf,
                BoundaryKind::LineEndLf,
                BoundaryKind::LineEndCrlf,
                BoundaryKind::InputEnd,
                BoundaryKind::WordAscii,
                BoundaryKind::NotWordAscii,
                BoundaryKind::WordStartAscii,
                BoundaryKind::WordEndAscii,
                BoundaryKind::WordStartHalfAscii,
                BoundaryKind::WordEndHalfAscii,
                BoundaryKind::WordUnicode,
                BoundaryKind::WordStartAscii,
                BoundaryKind::WordEndAscii,
                BoundaryKind::InputEnd,
            ]
        );
        assert!(analysis.invariants_hold(
            pattern,
            SemanticLimits::default(),
            FoldBoundaryLimits::default()
        ));
    }

    #[test]
    fn invalid_utf8_offsets_fail_closed_without_source_echo() {
        let error = BoundaryKind::WordUnicode
            .is_match("é", 1)
            .expect_err("mid-scalar offset must fail");
        assert_eq!(error.kind, BoundaryEvalErrorKind::InvalidUtf8Offset);
        assert_eq!(
            error.to_string(),
            "[RGX-FB-EVAL-E001] boundary evaluation failed"
        );
    }

    #[test]
    fn atom_range_total_and_boundary_budgets_fail_before_growth() {
        let atom_error = analyze(
            "(?i:ab)",
            LexerLimits::default(),
            ParserLimits::default(),
            SemanticLimits::default(),
            FoldBoundaryLimits {
                max_fold_atoms: 1,
                ..FoldBoundaryLimits::default()
            },
        )
        .expect_err("second fold atom must exceed budget");
        assert_eq!(atom_error.kind, FoldBoundaryErrorKind::FoldAtomLimit);

        let range_error = analyze(
            "(?i:a)",
            LexerLimits::default(),
            ParserLimits::default(),
            SemanticLimits::default(),
            FoldBoundaryLimits {
                max_ranges_per_fold: 1,
                ..FoldBoundaryLimits::default()
            },
        )
        .expect_err("ASCII case fold needs two singleton ranges");
        assert_eq!(range_error.kind, FoldBoundaryErrorKind::FoldRangeLimit);

        let total_error = analyze(
            "(?i:ab)",
            LexerLimits::default(),
            ParserLimits::default(),
            SemanticLimits::default(),
            FoldBoundaryLimits {
                max_total_fold_ranges: 2,
                ..FoldBoundaryLimits::default()
            },
        )
        .expect_err("aggregate ranges must exceed budget");
        assert_eq!(total_error.kind, FoldBoundaryErrorKind::TotalFoldRangeLimit);

        let boundary_error = analyze(
            r"\b\B",
            LexerLimits::default(),
            ParserLimits::default(),
            SemanticLimits::default(),
            FoldBoundaryLimits {
                max_boundary_assertions: 1,
                ..FoldBoundaryLimits::default()
            },
        )
        .expect_err("second boundary must exceed budget");
        assert_eq!(boundary_error.kind, FoldBoundaryErrorKind::BoundaryLimit);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn ascii_simple_fold_matches_independent_model(byte in 0_u8..=127) {
            let scalar = char::from(byte);
            let (plain, folded) = literal_outputs(
                LiteralAtom::Scalar(scalar),
                true,
                empty_span(),
            ).expect("retained ASCII fold available");
            prop_assert!(plain.matches_single_scalar(scalar));
            prop_assert!(folded.matches_single_scalar(scalar));
            if scalar.is_ascii_alphabetic() {
                prop_assert!(folded.matches_single_scalar(scalar.to_ascii_lowercase()));
                prop_assert!(folded.matches_single_scalar(scalar.to_ascii_uppercase()));
            } else {
                prop_assert_eq!(plain, folded);
            }
        }

        #[test]
        fn arbitrary_utf8_boundary_evaluation_is_deterministic_and_contained(
            haystack in any::<String>(),
            selector in any::<usize>(),
        ) {
            let boundaries = haystack
                .char_indices()
                .map(|(offset, _)| offset)
                .chain(core::iter::once(haystack.len()))
                .collect::<Vec<_>>();
            let offset = boundaries[selector % boundaries.len()];
            for kind in [
                BoundaryKind::InputStart,
                BoundaryKind::InputEnd,
                BoundaryKind::LineStartLf,
                BoundaryKind::LineEndLf,
                BoundaryKind::LineStartCrlf,
                BoundaryKind::LineEndCrlf,
                BoundaryKind::WordAscii,
                BoundaryKind::NotWordAscii,
                BoundaryKind::WordUnicode,
                BoundaryKind::NotWordUnicode,
            ] {
                let first = kind.is_match(&haystack, offset);
                let second = kind.is_match(&haystack, offset);
                prop_assert_eq!(first, second);
            }
        }
    }
