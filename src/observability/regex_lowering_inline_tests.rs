    use super::*;

    fn lower_default(pattern: &str) -> Result<Program, LowerError> {
        lower(
            pattern,
            LexerLimits::default(),
            ParserLimits::default(),
            SemanticLimits::default(),
            FoldBoundaryLimits::default(),
            CompileLimits::default(),
        )
    }

    fn compile_default(pattern: &str) -> Result<Program, PrivateCompileError> {
        compile_private(pattern, PrivateCompileLimits::default())
    }

    #[test]
    fn private_compile_facade_completes_the_r3_5_owned_syntax_rows() {
        for pattern in [
            "(?x)ab",
            "(?x:a\\ b)",
            "(?x)a b",
            "(?x)a # comment\n b",
            "(?x)[ a-z ]",
            "(?x)a{ 2 , 3 }",
            "(?x)\\x { 53 }",
            "(?x)\\p { Greek }",
            "(?x)( ?P<name> a )",
            "(?P<left>a)|(?P<right>b)",
        ] {
            let program = compile_default(pattern)
                .unwrap_or_else(|error| panic!("private compile rejected {pattern:?}: {error}"));
            program
                .validate(CompileLimits::default())
                .unwrap_or_else(|error| panic!("private IR invalid for {pattern:?}: {error}"));
        }

        let malformed = compile_default("(?x:").expect_err("unclosed flag scope must fail");
        assert_eq!(malformed.code(), "RGX-PARSE-E003");
        assert_eq!(malformed.stage(), PrivateCompileStage::Syntax);
    }

    #[test]
    fn private_compile_rejects_duplicate_names_without_retaining_source_text() {
        for pattern in [
            "(?P<r3_5_private_pattern_canary>a)|(?P<r3_5_private_pattern_canary>b)",
            "(?P<r3_5_private_pattern_canary>a)|(?<r3_5_private_pattern_canary>b)",
        ] {
            let error = compile_default(pattern).expect_err("duplicate capture name must fail");
            assert_eq!(error.code(), "RGX-PARSE-E013");
            assert_eq!(error.stage(), PrivateCompileStage::Syntax);
            assert_eq!(
                error.span().source(pattern),
                Some("r3_5_private_pattern_canary")
            );
            for rendered in [error.to_string(), format!("{error:?}")] {
                assert!(!rendered.contains("r3_5_private_pattern_canary"));
                assert!(!rendered.contains(pattern));
                assert!(rendered.contains("RGX-PARSE-E013"));
            }
        }
    }

    #[test]
    #[allow(clippy::literal_string_with_formatting_args)] // Regex property syntax uses braces.
    fn private_compile_aggregates_each_stage_and_retains_typed_defer_rows() {
        let syntax = compile_default("private-source-canary\\")
            .expect_err("trailing escape must fail in syntax");
        assert_eq!(syntax.code(), "RGX-LEX-E003");
        assert_eq!(syntax.stage(), PrivateCompileStage::Syntax);

        let semantic = compile_default(r"\p{DefinitelyNotAProperty}")
            .expect_err("unknown property must fail in semantics");
        assert_eq!(semantic.code(), "RGX-SEM-E001");
        assert_eq!(semantic.stage(), PrivateCompileStage::Semantics);

        let fold_boundary = compile_private(
            "(?i:ab)",
            PrivateCompileLimits {
                fold_boundary: FoldBoundaryLimits {
                    max_fold_atoms: 1,
                    ..FoldBoundaryLimits::default()
                },
                ..PrivateCompileLimits::default()
            },
        )
        .expect_err("second fold atom must exceed the private limit");
        assert_eq!(fold_boundary.code(), "RGX-FB-E003");
        assert_eq!(fold_boundary.stage(), PrivateCompileStage::FoldBoundary);

        let nullable = compile_default("(?:a?)*").expect_err("nullable loop remains deferred");
        assert_eq!(nullable.code(), "RGX-LOWER-E009");
        assert_eq!(nullable.stage(), PrivateCompileStage::Lowering);

        let erased = compile_default("(a){0}").expect_err("zero repeat capture remains deferred");
        assert_eq!(erased.code(), "RGX-LOWER-E010");
        assert_eq!(erased.stage(), PrivateCompileStage::Lowering);

        let dotted_age = compile_default(r"\p{Age:16.0}")
            .expect_err("dotted Age spelling remains explicitly deferred");
        assert_eq!(dotted_age.code(), "RGX-LEX-E004");
        assert_eq!(dotted_age.stage(), PrivateCompileStage::Syntax);

        let ir = compile_private(
            "ab",
            PrivateCompileLimits {
                ir: CompileLimits {
                    max_states: 2,
                    ..CompileLimits::default()
                },
                ..PrivateCompileLimits::default()
            },
        )
        .expect_err("two consumes plus accept exceed the private IR ceiling");
        assert_eq!(ir.code(), "RGX-IR-E005");
        assert_eq!(ir.stage(), PrivateCompileStage::IrValidation);
        assert_eq!(ir.actual(), Some(3));
        assert_eq!(ir.limit(), Some(2));

        for error in [
            syntax,
            semantic,
            fold_boundary,
            nullable,
            erased,
            dotted_age,
            ir,
        ] {
            let display = error.to_string();
            let debug = format!("{error:?}");
            assert!(!display.contains("private-source-canary"));
            assert!(!debug.contains("private-source-canary"));
            assert_eq!(
                display, debug,
                "Debug must not widen the diagnostic surface"
            );
        }
    }

    #[test]
    fn empty_literal_concat_and_classes_lower_to_checked_programs() {
        let empty = lower_default("").expect("empty expression");
        assert_eq!(empty.resources.states, 2);
        assert!(matches!(
            empty.states[empty.entry.index()].instruction,
            Instruction::Jump { target } if target == empty.accept
        ));

        let concat = lower_default(r"a[0-9]\p{Greek}.").expect("supported atoms");
        concat
            .validate(CompileLimits::default())
            .expect("lowered program validates");
        assert_eq!(concat.resources.states, 5);
        assert_eq!(concat.resources.classes, 4);
        assert!(
            concat
                .classes
                .iter()
                .all(|class| class.ranges.is_canonical())
        );
    }

    #[test]
    fn ordered_alternation_preserves_left_to_right_priority_and_empty_branches() {
        let program = lower_default("a|b|").expect("ordered alternation");
        let Instruction::Split {
            preferred,
            fallback,
        } = program.states[program.entry.index()].instruction
        else {
            panic!("entry must be the left-priority split");
        };
        assert!(matches!(
            program.states[preferred.index()].instruction,
            Instruction::Consume { class, .. }
                if program.classes[class.index()].ranges.contains_scalar('a')
        ));
        let Instruction::Split {
            preferred,
            fallback: final_fallback,
        } = program.states[fallback.index()].instruction
        else {
            panic!("fallback must retain the remaining branch order");
        };
        assert!(matches!(
            program.states[preferred.index()].instruction,
            Instruction::Consume { class, .. }
                if program.classes[class.index()].ranges.contains_scalar('b')
        ));
        assert!(matches!(
            program.states[final_fallback.index()].instruction,
            Instruction::Jump { .. }
        ));
    }

    #[test]
    fn folded_classes_exact_utf8_bytes_and_boundaries_use_r3_2_outputs() {
        let program = lower_default(r"(?i:[a-z])(?i-u:é)\A\b$").expect("fold and boundary outputs");
        assert_eq!(program.resources.classes, 3);
        assert_eq!(
            program
                .classes
                .iter()
                .filter(|class| matches!(class.ranges, CanonicalRanges::Bytes(_)))
                .count(),
            2,
            "the validated non-ASCII byte literal becomes its exact UTF-8 chain"
        );
        assert_eq!(
            program
                .states
                .iter()
                .filter(|state| matches!(state.instruction, Instruction::Assert { .. }))
                .count(),
            3
        );
    }

    #[test]
    fn deep_non_capturing_structure_is_iterative_and_deterministic() {
        let depth = 200;
        let pattern = format!("{}x{}", "(?:".repeat(depth), ")".repeat(depth));
        let parser_limits = ParserLimits {
            max_ast_nodes: 1_024,
            max_nesting: depth + 1,
        };
        let first = lower(
            &pattern,
            LexerLimits::default(),
            parser_limits,
            SemanticLimits::default(),
            FoldBoundaryLimits::default(),
            CompileLimits::default(),
        )
        .expect("bounded deep pattern");
        let second = lower(
            &pattern,
            LexerLimits::default(),
            parser_limits,
            SemanticLimits::default(),
            FoldBoundaryLimits::default(),
            CompileLimits::default(),
        )
        .expect("deterministic replay");
        assert_eq!(first, second);
        assert_eq!(first.resources.states, 2);
    }

    #[test]
    fn analysis_and_budget_failures_are_typed_span_aware_and_return_no_program() {
        let syntax = lower_default("(").expect_err("malformed pattern");
        assert!(matches!(
            syntax.kind,
            LowerErrorKind::Analysis(FoldBoundaryErrorKind::CharacterSemantics(_))
        ));
        assert_eq!(syntax.span.byte_start, 0);

        let budget = lower(
            "ab",
            LexerLimits::default(),
            ParserLimits::default(),
            SemanticLimits::default(),
            FoldBoundaryLimits::default(),
            CompileLimits {
                max_states: 2,
                ..CompileLimits::default()
            },
        )
        .expect_err("two consumes plus accept exceed the ceiling");
        assert_eq!(
            budget.kind,
            LowerErrorKind::Compile(CompileErrorKind::StateLimit)
        );
        assert_eq!(budget.actual, Some(3));
        assert_eq!(budget.limit, Some(2));
        assert!(budget.span.byte_end >= budget.span.byte_start);
    }

    #[test]
    fn captures_use_numbered_slot_pairs_and_zero_width_group_boundaries() {
        let program = lower_default("(a)(b)").expect("two captures");
        assert_eq!(program.capture_slots, 4);
        let mut saves = program
            .states
            .iter()
            .filter_map(|state| match state.instruction {
                Instruction::Save { slot, .. } => Some((slot.index(), state.source)),
                _ => None,
            })
            .collect::<Vec<_>>();
        saves.sort_unstable_by_key(|(slot, _)| *slot);
        assert_eq!(
            saves.iter().map(|(slot, _)| *slot).collect::<Vec<_>>(),
            [0, 1, 2, 3]
        );
        assert_eq!(saves[0].1, zero_width_span(0, 0));
        assert_eq!(saves[1].1, zero_width_span(3, 3));
        assert_eq!(saves[2].1, zero_width_span(3, 3));
        assert_eq!(saves[3].1, zero_width_span(6, 6));
    }

    #[test]
    fn quantifier_families_are_bounded_and_preserve_greedy_split_priority() {
        for pattern in ["a?", "a*", "a+", "a{0}", "a{3}", "a{2,}", "a{1,3}"] {
            lower_default(pattern)
                .unwrap_or_else(|error| panic!("{pattern} must lower: {error}"))
                .validate(CompileLimits::default())
                .unwrap_or_else(|error| panic!("{pattern} must validate: {error}"));
        }

        let zero = lower_default("a{0}").expect("zero count");
        assert_eq!(zero.resources.classes, 0);
        assert_eq!(zero.resources.states, 2);

        let exact = lower_default("a{3}").expect("exact count");
        assert_eq!(exact.repetition_expansion, 2);
        assert_eq!(exact.resources.classes, 1);

        let greedy = lower_default("a*").expect("greedy star");
        let Instruction::Split { preferred, .. } = greedy.states[greedy.entry.index()].instruction
        else {
            panic!("greedy star entry must split");
        };
        assert!(matches!(
            greedy.states[preferred.index()].instruction,
            Instruction::Consume { .. }
        ));

        let lazy = lower_default("a*?").expect("lazy star");
        let Instruction::Split { preferred, .. } = lazy.states[lazy.entry.index()].instruction
        else {
            panic!("lazy star entry must split");
        };
        assert!(matches!(
            lazy.states[preferred.index()].instruction,
            Instruction::Jump { .. }
        ));
    }

    #[test]
    fn scoped_flags_feed_r3_2_classes_and_hazards_fail_closed() {
        let scoped = lower_default("(?i:a)(?-i:b)").expect("scoped flags");
        assert!(scoped.classes[0].ranges.contains_scalar('A'));
        assert!(scoped.classes[0].ranges.contains_scalar('a'));
        assert!(scoped.classes[1].ranges.contains_scalar('b'));
        assert!(!scoped.classes[1].ranges.contains_scalar('B'));

        let nullable = lower_default("(?:a?)*").expect_err("nullable loop hazard");
        assert_eq!(nullable.kind, LowerErrorKind::NullableUnboundedRepetition);
        assert_eq!(nullable.code(), "RGX-LOWER-E009");

        let erased = lower_default("(a){0}").expect_err("zero repeat erases a capture");
        assert_eq!(erased.kind, LowerErrorKind::CaptureErasedByZeroRepetition);
        assert_eq!(erased.code(), "RGX-LOWER-E010");

        let repetition_limit = lower(
            "(?:ab){4}",
            LexerLimits::default(),
            ParserLimits::default(),
            SemanticLimits::default(),
            FoldBoundaryLimits::default(),
            CompileLimits {
                max_repetition_expansion: 4,
                ..CompileLimits::default()
            },
        )
        .expect_err("three two-state copies exceed four emitted states");
        assert_eq!(
            repetition_limit.kind,
            LowerErrorKind::Compile(CompileErrorKind::RepetitionLimit)
        );
        assert_eq!(repetition_limit.actual, Some(6));
        assert_eq!(repetition_limit.limit, Some(4));
    }
