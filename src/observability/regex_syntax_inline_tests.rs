    use super::*;
    use proptest::prelude::*;
    use regex::Regex as IncumbentRegex;

    fn default_lex(pattern: &str) -> Result<Vec<Token>, LexError> {
        lex(pattern, LexerLimits::default())
    }

    fn kinds(pattern: &str) -> Vec<TokenKind> {
        default_lex(pattern)
            .expect("fixture must lex")
            .into_iter()
            .map(|token| token.kind)
            .collect()
    }

    fn default_parse(pattern: &str) -> Result<Ast, SyntaxError> {
        parse(pattern, LexerLimits::default(), ParserLimits::default())
    }

    fn parse_error_kind(error: &SyntaxError) -> ParseErrorKind {
        match error {
            SyntaxError::Parse(error) => error.kind,
            SyntaxError::Lex(error) => panic!("expected parser error, got {error}"),
        }
    }

    fn diagnostic(error: &SyntaxError) -> (&'static str, SourceSpan) {
        match error {
            SyntaxError::Lex(error) => (error.kind.diagnostic_category(), error.span),
            SyntaxError::Parse(error) => (error.kind.diagnostic_category(), error.span),
        }
    }

    #[test]
    fn empty_pattern_is_an_explicit_zero_width_end_token() {
        let tokens = default_lex("").expect("empty pattern must lex");
        assert_eq!(
            tokens,
            vec![Token {
                kind: TokenKind::End,
                span: SourceSpan::empty_at(0, 0),
            }]
        );
    }

    #[test]
    fn lexes_top_level_operators_groups_flags_and_repetitions() {
        let pattern = "a|.(?:b)(?P<kind>c)(?<other>d)(?im-s:e)?*+{2}{3,}{4,5}^$";
        let tokens = default_lex(pattern).expect("operator fixture must lex");
        assert!(
            tokens
                .iter()
                .any(|token| token.kind == TokenKind::Alternation)
        );
        assert!(tokens.iter().any(|token| token.kind == TokenKind::Dot));
        assert!(
            tokens
                .iter()
                .any(|token| token.kind == TokenKind::NonCapturingGroupOpen)
        );
        assert!(tokens.iter().any(|token| matches!(
            token.kind,
            TokenKind::NamedCaptureGroupOpen {
                style: NamedCaptureStyle::Python,
                ..
            }
        )));
        assert!(tokens.iter().any(|token| matches!(
            token.kind,
            TokenKind::NamedCaptureGroupOpen {
                style: NamedCaptureStyle::Angle,
                ..
            }
        )));
        let flag = tokens
            .iter()
            .find_map(|token| match token.kind {
                TokenKind::FlagDirective { set, clear, scoped } => Some((set, clear, scoped)),
                _ => None,
            })
            .expect("flag token");
        assert!(flag.0.contains(Flag::CaseInsensitive));
        assert!(flag.0.contains(Flag::MultiLine));
        assert!(flag.1.contains(Flag::DotMatchesNewLine));
        assert!(flag.2);
        assert!(
            tokens
                .iter()
                .any(|token| { token.kind == TokenKind::Counted(RepetitionRange::Exact(2)) })
        );
        assert!(
            tokens
                .iter()
                .any(|token| { token.kind == TokenKind::Counted(RepetitionRange::AtLeast(3)) })
        );
        assert!(tokens.iter().any(|token| {
            token.kind == TokenKind::Counted(RepetitionRange::Bounded { min: 4, max: 5 })
        }));
    }

    #[test]
    fn named_capture_name_spans_are_borrowed_from_source() {
        let pattern = "(?P<κλειδί>x)";
        let tokens = default_lex(pattern).expect("Unicode capture name must lex");
        let name = tokens.iter().find_map(|token| match token.kind {
            TokenKind::NamedCaptureGroupOpen { name, .. } => name.source(pattern),
            _ => None,
        });
        assert_eq!(name, Some("κλειδί"));
    }

    #[test]
    fn byte_and_scalar_spans_round_trip_unicode_source() {
        let pattern = "é💩|x";
        let tokens = default_lex(pattern).expect("Unicode literal fixture must lex");
        assert_eq!(
            tokens[0].span,
            SourceSpan {
                byte_start: 0,
                byte_end: 2,
                scalar_start: 0,
                scalar_end: 1,
            }
        );
        assert_eq!(
            tokens[1].span,
            SourceSpan {
                byte_start: 2,
                byte_end: 6,
                scalar_start: 1,
                scalar_end: 2,
            }
        );
        assert_eq!(tokens[2].source(pattern), Some("|"));
        assert_eq!(tokens[3].source(pattern), Some("x"));
        assert_eq!(tokens[4].source(pattern), Some(""));
    }

    #[test]
    fn class_context_handles_leading_close_nested_classes_and_set_operators() {
        let pattern = "[]a&&[b]--c~~d-^]";
        let tokens = default_lex(pattern).expect("class fixture must lex");
        assert_eq!(tokens[0].kind, TokenKind::ClassOpen);
        assert_eq!(tokens[1].kind, TokenKind::Literal(']'));
        assert!(
            tokens
                .iter()
                .any(|token| token.kind == TokenKind::ClassIntersection)
        );
        assert!(
            tokens
                .iter()
                .any(|token| token.kind == TokenKind::ClassDifference)
        );
        assert!(
            tokens
                .iter()
                .any(|token| token.kind == TokenKind::ClassSymmetricDifference)
        );
        assert!(
            tokens
                .iter()
                .any(|token| token.kind == TokenKind::ClassRange)
        );
        assert_eq!(
            tokens
                .iter()
                .filter(|token| token.kind == TokenKind::ClassClose)
                .count(),
            2
        );
    }

    #[test]
    fn class_negation_posix_and_class_backspace_are_distinct() {
        let pattern = "[^[:^alpha:]\\b]";
        let tokens = default_lex(pattern).expect("POSIX fixture must lex");
        assert_eq!(tokens[1].kind, TokenKind::ClassNegation);
        let posix = tokens.iter().find_map(|token| match token.kind {
            TokenKind::PosixClass { negated, name } => Some((negated, name.source(pattern))),
            _ => None,
        });
        assert_eq!(posix, Some((true, Some("alpha"))));
        assert!(
            tokens
                .iter()
                .any(|token| { token.kind == TokenKind::Escaped(Escape::Control('\u{8}')) })
        );
    }

    #[test]
    fn lexes_every_declared_escape_family() {
        let pattern = "\\*\\a\\f\\t\\n\\r\\v\\x73\\u{1F4A9}\\d\\D\\s\\S\\w\\W\\p{Greek}\\PL\\A\\z\\b\\B\\b{start}\\b{end}\\b{start-half}\\b{end-half}\\<\\>";
        let tokens = default_lex(pattern).expect("escape fixture must lex");
        assert!(
            tokens
                .iter()
                .any(|token| { token.kind == TokenKind::Escaped(Escape::Literal('*')) })
        );
        assert!(
            tokens
                .iter()
                .any(|token| { token.kind == TokenKind::Escaped(Escape::Hex('s')) })
        );
        assert!(
            tokens
                .iter()
                .any(|token| { token.kind == TokenKind::Escaped(Escape::Unicode('💩')) })
        );
        assert!(tokens.iter().any(|token| {
            matches!(
                token.kind,
                TokenKind::Escaped(Escape::UnicodeClass { negated: false, .. })
            )
        }));
        assert!(tokens.iter().any(|token| {
            matches!(
                token.kind,
                TokenKind::Escaped(Escape::UnicodeClass { negated: true, .. })
            )
        }));
        for assertion in [
            Assertion::TextStart,
            Assertion::TextEnd,
            Assertion::WordBoundary,
            Assertion::NotWordBoundary,
            Assertion::WordStart,
            Assertion::WordEnd,
            Assertion::WordStartHalf,
            Assertion::WordEndHalf,
            Assertion::AsciiWordStart,
            Assertion::AsciiWordEnd,
        ] {
            assert!(
                tokens.iter().any(|token| {
                    token.kind == TokenKind::Escaped(Escape::Assertion(assertion))
                })
            );
        }
    }

    #[test]
    fn grammar_goldens_that_belong_to_lexer_all_tokenize() {
        for pattern in [
            "sam|samwise",
            "samwise|sam",
            "ab+?c",
            "(?P<kind>secret)-\\d+",
            "(?:ab){2,3}",
            "(?im-s:^x.$)",
            "[a-z&&[^aeiou]]+",
            "\\p{Greek}+",
            "\\x73\\u{65}cret",
            "(?-u:\\b)secret(?-u:\\b)",
            "",
            "(a+)+$",
        ] {
            let tokens = default_lex(pattern).unwrap_or_else(|error| {
                panic!("golden pattern failed with {error}");
            });
            assert_eq!(tokens.last().map(|token| token.kind), Some(TokenKind::End));
        }
    }

    #[test]
    fn stable_errors_cover_malformed_and_unsupported_inputs_without_source_text() {
        let cases = [
            ("\\", LexErrorKind::TrailingEscape),
            ("\\x0", LexErrorKind::MalformedEscape),
            ("\\xGG", LexErrorKind::MalformedEscape),
            ("\\u{}", LexErrorKind::MalformedEscape),
            ("\\u{D800}", LexErrorKind::InvalidUnicodeScalar),
            ("\\u{110000}", LexErrorKind::InvalidUnicodeScalar),
            ("\\q", LexErrorKind::MalformedEscape),
            ("\\1", LexErrorKind::UnsupportedBackreference),
            ("\\k<name>", LexErrorKind::UnsupportedBackreference),
            ("(?=x)", LexErrorKind::UnsupportedLookaround),
            ("(?<=x)", LexErrorKind::UnsupportedLookaround),
            ("(?q)", LexErrorKind::InvalidFlag),
            ("(?-)", LexErrorKind::InvalidFlag),
            ("a{3,2}", LexErrorKind::InvalidRepetition),
            ("a{4294967296}", LexErrorKind::InvalidRepetition),
        ];
        for (pattern, expected) in cases {
            let error = default_lex(pattern).expect_err("fixture must fail");
            assert_eq!(error.kind, expected);
            assert!(!error.to_string().contains(pattern));
            assert!(error.to_string().starts_with('['));
        }
    }

    #[test]
    fn repetition_u32_max_and_token_limit_boundaries_are_exact() {
        assert!(default_lex("a{4294967295}").is_ok());
        let limits = LexerLimits {
            max_pattern_bytes: 4,
            max_tokens: 4,
        };
        assert_eq!(
            lex("abc", limits).expect("three literals plus EOF").len(),
            4
        );
        let error = lex("abcd", limits).expect_err("EOF would exceed token budget");
        assert_eq!(error.kind, LexErrorKind::TokenLimit);
        assert_eq!(error.span, SourceSpan::empty_at(4, 4));
    }

    #[test]
    fn pattern_limit_rejects_before_tokenization_at_default_and_custom_bounds() {
        let limits = LexerLimits {
            max_pattern_bytes: 3,
            max_tokens: usize::MAX,
        };
        let error = lex("éé", limits).expect_err("four UTF-8 bytes exceed limit");
        assert_eq!(error.kind, LexErrorKind::PatternTooLarge);
        assert_eq!(error.span.byte_end, 4);
        assert_eq!(error.span.scalar_end, 2);

        let oversized = "a".repeat(DEFAULT_MAX_PATTERN_BYTES + 1);
        let error = default_lex(&oversized).expect_err("default pattern limit must apply");
        assert_eq!(error.kind, LexErrorKind::PatternTooLarge);
    }

    #[test]
    fn token_limit_also_bounds_adversarial_class_nesting() {
        let pattern = "[".repeat(128);
        let error = lex(
            &pattern,
            LexerLimits {
                max_pattern_bytes: pattern.len(),
                max_tokens: 16,
            },
        )
        .expect_err("class nesting cannot bypass token budget");
        assert_eq!(error.kind, LexErrorKind::TokenLimit);
        assert_eq!(error.span.byte_start, 16);
        assert_eq!(error.span.byte_end, 17);
    }

    #[test]
    fn minimized_fuzz_regressions_are_retained_and_replay_deterministically() {
        // Seed: 0x5A2C_0312. Replay:
        // cargo test --features metrics regex_syntax::tests::minimized_fuzz_regressions
        let corpus = [
            "",
            "\\",
            "\\u{",
            "\\u{D800}",
            "\\xF",
            "(?<",
            "(?--)",
            "[",
            "[]",
            "[^]",
            "[[:x:]]",
            "a{0,4294967295}",
            "a{4294967296}",
            "(?<!x)",
            "(x)\\9",
            "💩{2,3}",
        ];
        for pattern in corpus {
            let first = default_lex(pattern);
            let second = default_lex(pattern);
            assert_eq!(first, second, "nondeterministic replay");
        }
    }

    #[test]
    fn parser_accepts_every_frozen_positive_golden_with_reconciled_spans() {
        for pattern in [
            "sam|samwise",
            "samwise|sam",
            "ab+?c",
            "(?P<kind>secret)-\\d+",
            "(?:ab){2,3}",
            "(?im-s:^x.$)",
            "[a-z&&[^aeiou]]+",
            "\\p{Greek}+",
            "\\x73\\u{65}cret",
            "(?-u:\\b)secret(?-u:\\b)",
            "",
            "(a+)+$",
        ] {
            let ast = default_parse(pattern).unwrap_or_else(|error| {
                panic!("golden parser fixture failed with {error}");
            });
            assert!(ast.invariants_hold(pattern), "invalid AST for {pattern:?}");
            assert_eq!(ast.resources.ast_nodes, ast.nodes.len());
            assert_eq!(
                ast.node(ast.root).map(|node| node.span),
                Some(SourceSpan {
                    byte_start: 0,
                    byte_end: pattern.len(),
                    scalar_start: 0,
                    scalar_end: pattern.chars().count(),
                })
            );
        }
    }

    #[test]
    fn parser_flattens_ordered_precedence_without_reordering() {
        let ast = default_parse("a|bc|d").expect("precedence fixture must parse");
        let AstNodeKind::Alternation(branches) = &ast.node(ast.root).expect("root").kind else {
            panic!("root must be an alternation");
        };
        assert_eq!(branches.len(), 3);
        assert_eq!(
            ast.node(branches[0]).map(|node| &node.kind),
            Some(&AstNodeKind::Literal('a'))
        );
        let AstNodeKind::Concat(middle) = &ast.node(branches[1]).expect("middle branch").kind
        else {
            panic!("middle branch must be a concatenation");
        };
        assert_eq!(middle.len(), 2);
        assert_eq!(
            middle
                .iter()
                .filter_map(|id| ast.node(*id))
                .map(|node| &node.kind)
                .collect::<Vec<_>>(),
            vec![&AstNodeKind::Literal('b'), &AstNodeKind::Literal('c')]
        );
        assert_eq!(
            ast.node(branches[2]).map(|node| &node.kind),
            Some(&AstNodeKind::Literal('d'))
        );
    }

    #[test]
    fn parser_types_captures_flags_assertions_and_greediness() {
        let ast = default_parse("(?P<kind>a)(?:b)(?i-s:^c$)(?U)d+?")
            .expect("group and flag fixture must parse");
        assert!(ast.nodes.iter().any(|node| matches!(
            node.kind,
            AstNodeKind::Capture {
                index: 1,
                name: Some(_),
                style: Some(NamedCaptureStyle::Python),
                ..
            }
        )));
        assert!(
            ast.nodes
                .iter()
                .any(|node| matches!(node.kind, AstNodeKind::NonCapturing { .. }))
        );
        assert!(ast.nodes.iter().any(|node| matches!(
            node.kind,
            AstNodeKind::Flags {
                scoped: true,
                child: Some(_),
                ..
            }
        )));
        assert!(ast.nodes.iter().any(|node| matches!(
            node.kind,
            AstNodeKind::Flags {
                scoped: false,
                child: None,
                ..
            }
        )));
        let repetition = ast
            .nodes
            .iter()
            .find(|node| matches!(node.kind, AstNodeKind::Repetition { .. }))
            .expect("repetition");
        assert!(matches!(
            repetition.kind,
            AstNodeKind::Repetition {
                quantifier: Quantifier::OneOrMore,
                // U swaps the default, then the explicit suffix swaps it back.
                greediness: Greediness::Greedy,
                ..
            }
        ));
    }

    #[test]
    fn class_parser_preserves_range_union_negation_and_left_set_precedence() {
        let ast = default_parse("[a-z&&[^aeiou]--[x~~y]]").expect("class fixture must parse");
        let outer = ast
            .nodes
            .iter()
            .find(|node| {
                matches!(node.kind, AstNodeKind::Class { negated: false, .. })
                    && node.span.byte_start == 0
            })
            .expect("outer class");
        let AstNodeKind::Class { expression, .. } = outer.kind else {
            panic!("outer class kind");
        };
        let AstNodeKind::ClassSet {
            operator: ClassSetOperator::Difference,
            left,
            right,
        } = ast.node(expression).expect("class expression").kind
        else {
            panic!("outer set expression must be left-associated difference");
        };
        assert!(matches!(
            ast.node(left).map(|node| &node.kind),
            Some(AstNodeKind::ClassSet {
                operator: ClassSetOperator::Intersection,
                ..
            })
        ));
        assert!(matches!(
            ast.node(right).map(|node| &node.kind),
            Some(AstNodeKind::Class { negated: false, .. })
        ));
        assert!(
            ast.nodes
                .iter()
                .any(|node| matches!(node.kind, AstNodeKind::ClassRange { .. }))
        );
        assert!(
            ast.nodes
                .iter()
                .any(|node| matches!(node.kind, AstNodeKind::Class { negated: true, .. }))
        );
    }

    #[test]
    fn parser_reports_typed_structural_errors_with_stable_private_display() {
        let cases = [
            ("(", ParseErrorKind::UnclosedGroup),
            ("[", ParseErrorKind::UnclosedClass),
            (")", ParseErrorKind::UnexpectedGroupClose),
            ("*a", ParseErrorKind::InvalidRepetition),
            ("(?i)*", ParseErrorKind::InvalidRepetition),
            ("[\\A]", ParseErrorKind::InvalidClassEscape),
            ("[\\b]", ParseErrorKind::InvalidClassEscape),
            ("[a-\\d]", ParseErrorKind::InvalidClassRange),
            ("[\\w-a]", ParseErrorKind::InvalidClassRange),
            ("[z-a]", ParseErrorKind::InvalidClassRange),
        ];
        for (pattern, expected) in cases {
            let error = default_parse(pattern).expect_err("fixture must fail");
            assert_eq!(parse_error_kind(&error), expected, "pattern {pattern:?}");
            assert!(error.to_string().starts_with("[RGX-PARSE-E"));
        }

        let private_pattern = "(private-source-canary";
        let rendered = default_parse(private_pattern)
            .expect_err("unclosed private pattern must fail")
            .to_string();
        assert!(!rendered.contains("private-source-canary"));

        let error = default_parse("\\").expect_err("lexer failure must be retained");
        assert!(matches!(
            error,
            SyntaxError::Lex(LexError {
                kind: LexErrorKind::TrailingEscape,
                ..
            })
        ));
    }

    #[test]
    fn frozen_invalid_goldens_match_diagnostic_category_and_span() {
        let cases = [
            ("(?=secret)", "RGX-DIAG-UNSUPPORTED-LOOKAROUND", (0, 3)),
            ("(secret)\\1", "RGX-DIAG-UNSUPPORTED-BACKREFERENCE", (8, 10)),
            ("(", "RGX-DIAG-UNCLOSED-GROUP", (0, 1)),
            ("[", "RGX-DIAG-UNCLOSED-CLASS", (0, 1)),
            ("a{3,2}", "RGX-DIAG-INVALID-REPETITION", (1, 6)),
            ("(?q)secret", "RGX-DIAG-INVALID-FLAG", (2, 3)),
            ("(?-u:.)", "RGX-DIAG-INVALID-UTF8", (0, 7)),
            ("\\", "RGX-DIAG-TRAILING-ESCAPE", (0, 1)),
        ];
        for (pattern, expected_category, (byte_start, byte_end)) in cases {
            let error = default_parse(pattern).expect_err("invalid golden must fail");
            let (category, span) = diagnostic(&error);
            assert_eq!(category, expected_category, "pattern {pattern:?}");
            assert_eq!(
                (span.byte_start, span.byte_end),
                (byte_start, byte_end),
                "pattern {pattern:?}"
            );
        }
    }

    #[test]
    fn directly_nested_repetition_matches_incumbent_syntax_and_stays_bounded() {
        for pattern in ["a**", "a++", "a{1}+", "a+{2}"] {
            assert!(
                IncumbentRegex::new(pattern).is_ok(),
                "incumbent drifted for {pattern:?}"
            );
            let ast = default_parse(pattern).expect("direct nested repetition must parse");
            assert!(ast.invariants_hold(pattern));
            assert_eq!(ast.resources.repetition_operators, 2);
            assert_eq!(
                ast.nodes
                    .iter()
                    .filter(|node| matches!(node.kind, AstNodeKind::Repetition { .. }))
                    .count(),
                2
            );
        }

        let SyntaxError::Parse(error) =
            default_parse("(?i)*").expect_err("a flag directive is not repeatable")
        else {
            panic!("expected parser error");
        };
        assert_eq!(error.kind, ParseErrorKind::InvalidRepetition);
        assert_eq!(
            error.span,
            SourceSpan {
                byte_start: 4,
                byte_end: 4,
                scalar_start: 4,
                scalar_end: 4,
            }
        );
    }

    #[test]
    fn class_set_operators_preserve_incumbent_empty_operands() {
        for pattern in ["[a&&]", "[&&a]", "[a--]", "[--a]", "[a~~]", "[~~a]"] {
            assert!(
                IncumbentRegex::new(pattern).is_ok(),
                "incumbent drifted for {pattern:?}"
            );
            let ast = default_parse(pattern).expect("empty set operand must parse");
            assert!(ast.invariants_hold(pattern));
            assert!(ast.nodes.iter().any(|node| matches!(
                &node.kind,
                AstNodeKind::ClassUnion(children) if children.is_empty()
            )));
            assert!(
                ast.nodes
                    .iter()
                    .any(|node| matches!(node.kind, AstNodeKind::ClassSet { .. }))
            );
        }
    }

    #[test]
    fn quarantined_incumbent_and_candidate_compile_states_match_adversarial_corpus() {
        let corpus = [
            "token-[A-F0-9]{8}",
            "cat|dog",
            "(?P<kind>secret)-\\d+",
            "(?:ab){2,3}",
            "\\Asecret\\z",
            "(?m)^secret$",
            "(?s)BEGIN.*END",
            "(?mR)^secret$",
            "(?i)σ",
            "(?x) secret \\s+ \\d+",
            "(?U)a+",
            "\\p{Greek}+",
            "\\d+",
            "[[:digit:]]+",
            "[a-z&&[^aeiou]]+",
            "[0-9--4]+",
            "[a-g~~b-h]+",
            "\\bκόσμος\\b",
            "(?-u:\\b)secret(?-u:\\b)",
            "\\x73\\u{65}cret",
            "",
            "^",
            "[a&&b]",
            "(a+)+$",
            "(?=secret)",
            "(secret)\\1",
            "(",
            "[",
            "a{3,2}",
            "(?q)secret",
            "(?x:a # comment\n b)",
            "(?x)[ a-z ]",
            "(?x)a{ 2 , 3 }",
            "(?x)\\x { 53 }",
            "(?x)\\u { 53 }",
            "(?x)\\p { Greek }",
            "(?x)( ?P<foo> a )",
            "(?x)( ?: a )",
            "(?x:\\ )",
            "(?P<name>a)|(?P<name>b)",
            "^*",
            "\\b+",
            "(?i)*",
            "a**",
            "a{1}+",
            "[a-\\d]",
            "[\\w-a]",
            "[z-a]",
            "[\\A]",
            "[\\b]",
            "[a&&]",
            "[&&a]",
            "[a--]",
            "[--a]",
            "[a~~]",
            "[~~a]",
            "\\p{DefinitelyNotAProperty}",
            "[[:definitelynot:]]",
            "(?-u:\\pL)",
            "(?-u:\\xFF)",
            "(?>a)",
            "a++",
        ];
        let mismatches = corpus
            .iter()
            .filter_map(|pattern| {
                let incumbent = IncumbentRegex::new(pattern).is_ok();
                let candidate = default_parse(pattern).is_ok();
                (incumbent != candidate).then_some((*pattern, incumbent, candidate))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            mismatches,
            vec![
                ("\\p{DefinitelyNotAProperty}", false, true),
                ("(?-u:\\pL)", false, true),
                ("(?-u:\\xFF)", false, true),
            ],
            "quarantined oracle divergence set drifted"
        );
    }

    // The incumbent patterns below are deliberately trivial. This test pins
    // incumbent `(?x)` whitespace/comment semantics against the candidate
    // parser, so `clippy::trivial_regex`'s suggestion to use plain string
    // operations would delete the exact behavior under test. Suppressed rather
    // than "simplified" (br-asupersync-vdbvkv chain; raised with the R3.1.4
    // owner in Agent Mail thread asupersync-5z2scg.8.3.1.4 before landing).
    #[allow(clippy::trivial_regex)]
    #[test]
    fn extended_mode_elides_only_grammar_ignored_text_and_preserves_spans() {
        let incumbent = IncumbentRegex::new("(?x)a b").expect("incumbent x pattern");
        assert!(incumbent.is_match("ab"));
        assert!(!incumbent.is_match("a b"));
        let whitespace = default_parse("(?x)a b").expect("candidate accepts global x");
        assert!(
            !whitespace
                .nodes
                .iter()
                .any(|node| matches!(node.kind, AstNodeKind::Literal(' '))),
            "unescaped whitespace must be absent from the AST"
        );

        let incumbent = IncumbentRegex::new("(?x)a # comment\n b").expect("incumbent x comment");
        assert!(incumbent.is_match("ab"));
        let comment = default_parse("(?x)a # comment\n b").expect("candidate accepts x comment");
        assert!(
            !comment
                .nodes
                .iter()
                .any(|node| matches!(node.kind, AstNodeKind::Literal('#'))),
            "verbose comments must be absent from the AST"
        );

        let incumbent = IncumbentRegex::new("(?x)[ a-z ]").expect("incumbent x class");
        assert!(incumbent.is_match("a"));
        assert!(!incumbent.is_match(" "));
        let class = default_parse("(?x)[ a-z ]").expect("candidate accepts x class");
        assert!(
            !class
                .nodes
                .iter()
                .any(|node| matches!(node.kind, AstNodeKind::ClassLiteral(' '))),
            "verbose class whitespace must be absent from the AST"
        );

        let incumbent = IncumbentRegex::new("(?x)( ?P<foo> a )").expect("incumbent spaced capture");
        assert_eq!(
            incumbent.capture_names().flatten().collect::<Vec<_>>(),
            ["foo"]
        );
        let capture = default_parse("(?x)( ?P<foo> a )").expect("candidate accepts spaced group");
        assert!(
            capture
                .nodes
                .iter()
                .any(|node| matches!(node.kind, AstNodeKind::Capture { name: Some(_), .. })),
            "verbose group-prefix whitespace must preserve named capture metadata"
        );

        let escaped = default_parse("(?x:a\\ b)").expect("escaped space remains literal");
        assert!(
            escaped
                .nodes
                .iter()
                .any(|node| matches!(node.kind, AstNodeKind::Escape(Escape::Literal(' '))))
        );

        let scoped = default_parse("(?x:a (?-x: b ) c)").expect("scoped x disable");
        assert_eq!(
            scoped
                .nodes
                .iter()
                .filter(|node| matches!(node.kind, AstNodeKind::Literal(' ')))
                .count(),
            2,
            "only spaces in the explicitly x-disabled scope remain literals"
        );

        for pattern in [
            "(?x)a{ 2 , 3 }",
            "(?x)\\x { 53 }",
            "(?x)\\u { 53 }",
            "(?x)\\p { Greek }",
            "(?x)( ?: a )",
        ] {
            let candidate = default_parse(pattern)
                .unwrap_or_else(|error| panic!("candidate rejected {pattern:?}: {error}"));
            assert!(candidate.invariants_hold(pattern));
            assert!(
                IncumbentRegex::new(pattern).is_ok(),
                "incumbent rejected owned verbose fixture {pattern:?}"
            );
        }

        let malformed = default_parse("(?x:").expect_err("unclosed scoped flag group");
        assert_eq!(parse_error_kind(&malformed), ParseErrorKind::UnclosedGroup);
    }

    #[test]
    fn duplicate_capture_names_fail_with_a_stable_secret_safe_code() {
        default_parse("(?P<left>a)|(?P<right>b)").expect("distinct names are valid");

        for pattern in [
            "(?P<r3_5_private_pattern_canary>a)|(?P<r3_5_private_pattern_canary>b)",
            "(?P<r3_5_private_pattern_canary>a)|(?<r3_5_private_pattern_canary>b)",
        ] {
            let error = default_parse(pattern).expect_err("duplicate name must fail");
            let SyntaxError::Parse(error) = error else {
                panic!("duplicate name must be a parser error");
            };
            assert_eq!(error.kind, ParseErrorKind::DuplicateCaptureName);
            assert_eq!(error.kind.code(), "RGX-PARSE-E013");
            assert_eq!(
                error.kind.diagnostic_category(),
                "RGX-DIAG-DUPLICATE-CAPTURE-NAME"
            );
            assert_eq!(
                error.span.source(pattern),
                Some("r3_5_private_pattern_canary")
            );
            assert!(!error.to_string().contains("r3_5_private_pattern_canary"));
            assert!(!format!("{error:?}").contains("r3_5_private_pattern_canary"));
        }

        let empty = default_parse("(?P<>a)").expect_err("empty name remains malformed");
        assert!(matches!(
            empty,
            SyntaxError::Lex(LexError {
                kind: LexErrorKind::MalformedGroupPrefix,
                ..
            })
        ));
    }

    #[test]
    fn invalid_class_ranges_report_the_canonical_endpoint_span() {
        let cases = [
            (
                "[a-\\d]",
                SourceSpan {
                    byte_start: 3,
                    byte_end: 5,
                    scalar_start: 3,
                    scalar_end: 5,
                },
            ),
            (
                "[\\w-a]",
                SourceSpan {
                    byte_start: 1,
                    byte_end: 3,
                    scalar_start: 1,
                    scalar_end: 3,
                },
            ),
            (
                "[z-a]",
                SourceSpan {
                    byte_start: 1,
                    byte_end: 4,
                    scalar_start: 1,
                    scalar_end: 4,
                },
            ),
        ];
        for (pattern, expected_span) in cases {
            let SyntaxError::Parse(error) =
                default_parse(pattern).expect_err("invalid class range must fail")
            else {
                panic!("expected parser error");
            };
            assert_eq!(error.kind, ParseErrorKind::InvalidClassRange);
            assert_eq!(error.span, expected_span, "pattern {pattern:?}");
        }
    }

    #[test]
    fn unicode_disablement_rejects_unsafe_dot_at_the_scoped_group_span() {
        let error = default_parse("(?-u:.)").expect_err("byte-mode dot violates UTF-8");
        let SyntaxError::Parse(error) = error else {
            panic!("expected parser error");
        };
        assert_eq!(error.kind, ParseErrorKind::InvalidUtf8Invariant);
        assert_eq!(
            error.span,
            SourceSpan {
                byte_start: 0,
                byte_end: 7,
                scalar_start: 0,
                scalar_end: 7,
            }
        );
        assert!(default_parse("(?-u:\\b)").is_ok());
        assert_eq!(
            parse_error_kind(&default_parse("(?-u).").expect_err("global byte dot")),
            ParseErrorKind::InvalidUtf8Invariant
        );
    }

    #[test]
    fn parser_node_and_nesting_limits_are_exact_and_preallocation_safe() {
        let one = parse(
            "a",
            LexerLimits::default(),
            ParserLimits {
                max_ast_nodes: 1,
                max_nesting: DEFAULT_MAX_NESTING,
            },
        )
        .expect("one literal needs one node");
        assert_eq!(one.nodes.len(), 1);

        let error = parse(
            "ab",
            LexerLimits::default(),
            ParserLimits {
                max_ast_nodes: 2,
                max_nesting: DEFAULT_MAX_NESTING,
            },
        )
        .expect_err("concat node would exceed limit");
        assert_eq!(parse_error_kind(&error), ParseErrorKind::AstNodeLimit);

        let mut at_limit = "(".repeat(DEFAULT_MAX_NESTING);
        at_limit.push('a');
        at_limit.push_str(&")".repeat(DEFAULT_MAX_NESTING));
        let ast = default_parse(&at_limit).expect("exact nesting limit");
        assert_eq!(ast.resources.max_nesting, DEFAULT_MAX_NESTING);

        let mut above_limit = "(".repeat(DEFAULT_MAX_NESTING + 1);
        above_limit.push('a');
        above_limit.push_str(&")".repeat(DEFAULT_MAX_NESTING + 1));
        let error = default_parse(&above_limit).expect_err("nesting limit must fail");
        assert_eq!(parse_error_kind(&error), ParseErrorKind::NestingLimit);
    }

    #[test]
    fn repetition_accounting_is_bounded_without_ast_expansion() {
        let ast = default_parse("(a{2}){3}").expect("nested counted repetition");
        assert_eq!(ast.resources.repetition_operators, 2);
        assert_eq!(
            ast.resources.repetition_expansion,
            ExpansionEstimate {
                minimum: ExpansionBound::Finite(6),
                maximum: ExpansionBound::Finite(6),
            }
        );

        let unbounded = default_parse("a*").expect("unbounded repetition");
        assert_eq!(
            unbounded.resources.repetition_expansion.maximum,
            ExpansionBound::Unbounded
        );

        let maximum = u32::MAX;
        let pattern =
            format!("((((a{{{maximum}}}){{{maximum}}}){{{maximum}}}){{{maximum}}}){{{maximum}}}");
        let overflowed = default_parse(&pattern).expect("accounting overflow is represented");
        assert_eq!(
            overflowed.resources.repetition_expansion.maximum,
            ExpansionBound::Overflowed
        );
        assert!(
            overflowed.nodes.len() < 32,
            "repetitions must never allocate expanded copies"
        );
    }

    #[test]
    fn minimized_parser_regressions_are_retained_and_replay_deterministically() {
        // Seed: 0x5A2C_0313. Replay:
        // cargo test --features metrics regex_syntax::tests::minimized_parser_regressions
        let corpus = [
            "",
            "|",
            "a|",
            "|a",
            "()",
            "(a",
            "a)",
            "a??",
            "a???",
            "[a-z]",
            "[-a]",
            "[a-]",
            "[\\A]",
            "[\\b]",
            "[a-\\d]",
            "[\\w-a]",
            "[z-a]",
            "[a&&b]",
            "[a&&]",
            "[a-z&&[^aeiou]]",
            "(?-u:.)",
            "(?-u:\\b)",
            "(a{4294967295}){4294967295}",
        ];
        for pattern in corpus {
            let first = default_parse(pattern);
            let second = default_parse(pattern);
            assert_eq!(first, second, "nondeterministic parser replay");
            if let Ok(ast) = first {
                assert!(ast.invariants_hold(pattern));
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn literal_token_spans_round_trip_for_arbitrary_unicode(
            scalars in proptest::collection::vec(
                any::<char>().prop_filter("exclude regex metacharacters", |value| {
                    !matches!(value, '|' | '.' | '(' | ')' | '[' | '?' | '*' | '+' | '{' | '^' | '$' | '\\')
                }),
                0..128,
            ),
        ) {
            let pattern: String = scalars.iter().collect();
            let tokens = default_lex(&pattern).expect("literal-only pattern must lex");
            prop_assert_eq!(tokens.len(), scalars.len() + 1);
            for (token, expected) in tokens.iter().zip(scalars.iter()) {
                prop_assert_eq!(token.kind, TokenKind::Literal(*expected));
                let mut encoded = [0_u8; 4];
                let expected_source: &str = expected.encode_utf8(&mut encoded);
                prop_assert_eq!(token.source(&pattern), Some(expected_source));
            }
            prop_assert_eq!(tokens.last().map(|token| token.kind), Some(TokenKind::End));
        }

        #[test]
        fn arbitrary_utf8_is_panic_free_deterministic_and_span_safe(pattern in any::<String>()) {
            let first = default_lex(&pattern);
            let second = default_lex(&pattern);
            prop_assert_eq!(&first, &second);
            if let Ok(tokens) = first {
                for token in tokens {
                    prop_assert!(token.span.byte_start <= token.span.byte_end);
                    prop_assert!(token.span.scalar_start <= token.span.scalar_end);
                    prop_assert!(token.source(&pattern).is_some());
                }
            }
        }

        #[test]
        fn arbitrary_utf8_parser_is_deterministic_panic_free_and_reconciled(
            pattern in any::<String>(),
        ) {
            let first = default_parse(&pattern);
            let second = default_parse(&pattern);
            prop_assert_eq!(&first, &second);
            if let Ok(ast) = first {
                prop_assert!(ast.invariants_hold(&pattern));
                prop_assert!(ast.resources.max_nesting <= DEFAULT_MAX_NESTING);
                prop_assert!(ast.resources.ast_nodes <= DEFAULT_MAX_AST_NODES);
            }
        }

        #[test]
        fn alternation_and_concatenation_match_the_flat_precedence_model(
            segments in proptest::collection::vec("[a-z]{1,8}", 1..8),
        ) {
            let pattern = segments.join("|");
            let ast = default_parse(&pattern).expect("model pattern must parse");
            prop_assert!(ast.invariants_hold(&pattern));
            if segments.len() == 1 {
                prop_assert!(!matches!(
                    ast.node(ast.root).map(|node| &node.kind),
                    Some(AstNodeKind::Alternation(_))
                ));
            } else {
                let Some(AstNode {
                    kind: AstNodeKind::Alternation(branches),
                    ..
                }) = ast.node(ast.root)
                else {
                    return Err(TestCaseError::fail("root must be an alternation"));
                };
                prop_assert_eq!(branches.len(), segments.len());
            }
        }
    }

    #[test]
    fn grammar_identifier_and_default_limits_match_frozen_contract() {
        assert_eq!(GRAMMAR_ID, "ASUP-REGEX-SYNTAX-V1");
        assert_eq!(
            LexerLimits::default(),
            LexerLimits {
                max_pattern_bytes: 1_048_576,
                max_tokens: 1_048_576,
            }
        );
        assert_eq!(
            ParserLimits::default(),
            ParserLimits {
                max_ast_nodes: 1_048_576,
                max_nesting: 250,
            }
        );
    }

    #[test]
    fn every_token_span_round_trips_for_mixed_fixture() {
        let pattern = "(?i:a💩)[^x-z]\\p{Greek}{2,3}|$";
        for token in default_lex(pattern).expect("mixed fixture must lex") {
            assert!(token.source(pattern).is_some());
            assert!(pattern.is_char_boundary(token.span.byte_start));
            assert!(pattern.is_char_boundary(token.span.byte_end));
        }
    }

    #[test]
    fn top_level_token_kind_snapshot_is_stable() {
        assert_eq!(
            kinds("a|b.*?+$"),
            vec![
                TokenKind::Literal('a'),
                TokenKind::Alternation,
                TokenKind::Literal('b'),
                TokenKind::Dot,
                TokenKind::ZeroOrMore,
                TokenKind::ZeroOrOne,
                TokenKind::OneOrMore,
                TokenKind::LineEnd,
                TokenKind::End,
            ]
        );
    }
